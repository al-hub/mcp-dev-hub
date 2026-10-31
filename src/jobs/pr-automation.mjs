// Durable PR-level gate controller. No remote side effects: the Worker must reconcile
// each requested action and record evidence before advancing to the next gate.
const SHA=/^[0-9a-f]{40}$/;
const KEY=/^[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+#[1-9][0-9]*$/;
const GATES=['ci','independent_review','security','private_sse','pc','galaxy'];
export function ensurePrAutomation(db){
 db.exec(`CREATE TABLE IF NOT EXISTS pr_automation (
  pr_key TEXT PRIMARY KEY, head_sha TEXT NOT NULL, state TEXT NOT NULL,
  updated_at TEXT NOT NULL
 ); CREATE TABLE IF NOT EXISTS pr_gate_evidence (
  pr_key TEXT NOT NULL, gate TEXT NOT NULL, head_sha TEXT NOT NULL,
  verdict TEXT NOT NULL, evidence_id TEXT NOT NULL, updated_at TEXT NOT NULL,
  PRIMARY KEY(pr_key,gate), FOREIGN KEY(pr_key) REFERENCES pr_automation(pr_key)
 )`);
}
export function trackPr(db,{prKey,headSha,now=new Date().toISOString()}){
 if(!KEY.test(prKey)||!SHA.test(headSha))throw Error('invalid PR identity');
 ensurePrAutomation(db);
 db.exec('BEGIN IMMEDIATE');
 try{
  const before=db.prepare('SELECT head_sha FROM pr_automation WHERE pr_key=?').get(prKey);
  db.prepare(`INSERT INTO pr_automation(pr_key,head_sha,state,updated_at)
   VALUES(?,?,'verifying',?) ON CONFLICT(pr_key) DO UPDATE SET
   head_sha=excluded.head_sha,state=CASE WHEN head_sha=excluded.head_sha THEN state ELSE 'verifying' END,
   updated_at=excluded.updated_at`).run(prKey,headSha,now);
  if(before && before.head_sha!==headSha)
   db.prepare('DELETE FROM pr_gate_evidence WHERE pr_key=?').run(prKey);
  db.exec('COMMIT');return {changed:Boolean(before&&before.head_sha!==headSha)};
 }catch(e){db.exec('ROLLBACK');throw e;}
}
export function recordPrGate(db,{prKey,headSha,gate,verdict,evidenceId,now=new Date().toISOString()}){
 if(!KEY.test(prKey)||!SHA.test(headSha)||!GATES.includes(gate)||
    !['passed','failed','blocked'].includes(verdict)||typeof evidenceId!=='string'||
    !/^[A-Za-z0-9][A-Za-z0-9_.:\/-]{2,255}$/.test(evidenceId))throw Error('invalid gate evidence');
 ensurePrAutomation(db);
 const current=db.prepare('SELECT head_sha FROM pr_automation WHERE pr_key=?').get(prKey);
 if(!current||current.head_sha!==headSha)throw Error('stale or untracked PR SHA');
 db.prepare(`INSERT INTO pr_gate_evidence(pr_key,gate,head_sha,verdict,evidence_id,updated_at)
   VALUES(?,?,?,?,?,?) ON CONFLICT(pr_key,gate) DO UPDATE SET
   head_sha=excluded.head_sha,verdict=excluded.verdict,
   evidence_id=excluded.evidence_id,updated_at=excluded.updated_at`)
 .run(prKey,gate,headSha,verdict,evidenceId,now);
}
export function prNextAction(db,{prKey,observedSha}){
 if(!KEY.test(prKey)||!SHA.test(observedSha))throw Error('invalid PR');
 ensurePrAutomation(db);
 const pr=db.prepare('SELECT * FROM pr_automation WHERE pr_key=?').get(prKey);
 if(!pr)return {state:'untracked',action:'register'};
 if(pr.head_sha!==observedSha)return {state:'stale_sha',action:'reconcile'};
 const rows=db.prepare('SELECT gate,verdict,evidence_id FROM pr_gate_evidence WHERE pr_key=?').all(prKey);
 const statuses=new Map(rows.map(x=>[x.gate,x]));
 for(const gate of GATES){
  const v=statuses.get(gate);
  if(!v)return {state:'verifying',action:'verify',gate};
  if(v.verdict!=='passed')return {state:v.verdict,action:'remediate_or_block',gate};
 }
 return {state:'merge_eligible',action:'request_guarded_merge',headSha:observedSha};
}
