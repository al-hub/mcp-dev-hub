import {decideCiRemediation} from './ci-remediation.mjs';
export function ensureRemediationTable(db){
 db.exec(`CREATE TABLE IF NOT EXISTS ci_remediations (
  pr_key TEXT PRIMARY KEY, head_sha TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 3),
  state TEXT NOT NULL, reason TEXT, updated_at TEXT NOT NULL
 )`);
}
// Claim one correction atomically before an AI CLI is invoked.
// Uncertain or interrupted claims stay held for reconciliation.
export function claimCiRemediation(db,{prKey,headSha,observedSha,reason,reviewerIndependent,at=Date.now()}){
 if(!/^[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+#[1-9][0-9]*$/.test(prKey)||!Number.isFinite(at))throw Error('invalid PR key');
 ensureRemediationTable(db);
 db.exec('BEGIN IMMEDIATE');
 try{
  const row=db.prepare('SELECT * FROM ci_remediations WHERE pr_key=?').get(prKey);
  if(row && (row.state==='dispatching'||row.state==='unknown'||row.state==='awaiting_new_sha')){
   db.exec('COMMIT');return {state:row.state,allowed:false,attempts:row.attempts};
  }
  if(row && row.head_sha!==headSha){db.exec('COMMIT');return {state:'reconcile',allowed:false};}
  const attempts=row?.attempts??0;
  const d=decideCiRemediation({attempts,reason,headSha,observedSha,reviewerIndependent});
  const state=d.allowed?'dispatching':d.state;
  db.prepare(`INSERT INTO ci_remediations(pr_key,head_sha,attempts,state,reason,updated_at)
    VALUES(?,?,?,?,?,?) ON CONFLICT(pr_key) DO UPDATE SET attempts=excluded.attempts,
    state=excluded.state,reason=excluded.reason,updated_at=excluded.updated_at`)
    .run(prKey,headSha,d.allowed?d.nextAttempt:attempts,state,reason,new Date(at).toISOString());
  db.exec('COMMIT');return {...d,state};
 }catch(e){db.exec('ROLLBACK');throw e;}
}
export function acknowledgeCiFix(db,{prKey,newSha,dispatched}){
 ensureRemediationTable(db);
 const row=db.prepare('SELECT * FROM ci_remediations WHERE pr_key=?').get(prKey);
 if(!row||row.state!=='dispatching')return false;
 if(!dispatched){db.prepare("UPDATE ci_remediations SET state='unknown' WHERE pr_key=?").run(prKey);return false;}
 if(!/^[a-f0-9]{40}$/.test(newSha??'')||newSha===row.head_sha){
  db.prepare("UPDATE ci_remediations SET state='awaiting_new_sha' WHERE pr_key=?").run(prKey);return false;
 }
 db.prepare("UPDATE ci_remediations SET head_sha=?,state='verification_required' WHERE pr_key=?").run(newSha,prKey);
 return true;
}
