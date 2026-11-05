// #23 narrowly authorized GitHub-only AI canary. No checkout-controlled
// source, npm script, shell, or test may execute on the Worker host.
export const CANARY_JOB_ID='canary-23-20261105';
export const CANARY_REPO='al-hub/mcp-dev-hub';
export const CANARY_BRANCH='test/23-worker-canary-20261105';
export const CANARY_PATH='tests/dashboard-bearer-minimum-24.test.mjs';
export const SHA=/^[0-9a-f]{40}$/;
const stages=['started','branch_dispatching','branch_created','source_generated',
 'content_dispatching','content_uploaded','pr_dispatching','pr_created',
 'ci_passed','review_dispatching','review_passed',
 'merge_dispatching','merged','succeeded'];
export function canaryAuthorized({job,scope,write,push,enabled}={}){
 return job?.id===CANARY_JOB_ID&&job.kind==='ai-github-canary'&&
   ['queued','starting','running'].includes(job.state)&&
   job.target==='local'&&[job.project,job.target,job.workspace].join(':')===scope&&
   write==='1'&&push==='1'&&enabled==='1';
}
export function validateCandidate(source){
 if(typeof source!=='string'||source.length<150||source.length>7000||
   source.includes('\0')||source.includes(String.fromCharCode(96).repeat(3))||source.includes('\r')||
   !source.trimStart().startsWith('import ')||!source.includes('safeBearer')||
   !source.includes('24')||!source.includes('23')||
   !source.includes('test(')||!source.includes('assert.'))return false;
 if(/\b(?:process|globalThis|eval|Function|require|fetch|WebSocket|XMLHttpRequest|Buffer|child_process|exec|spawn|readFile|writeFile|import\s*\(|https?:\/\/)\b/i.test(source))
  return false;
 const imports=[...source.matchAll(/\bfrom\s+(['"])([^'"]+)\1/g)].map(m=>m[2]);
 return imports.length===3&&new Set(imports).size===3&&
  ['node:test','node:assert/strict','../src/dashboard/read-only-server.mjs']
    .every(p=>imports.includes(p));
}
export function ensureCanaryTable(db){
 db.exec('CREATE TABLE IF NOT EXISTS ai_github_canary ('+
  'job_id TEXT PRIMARY KEY, phase TEXT NOT NULL, base_sha TEXT NOT NULL,'+
  'head_sha TEXT, pr_number INTEGER, merge_sha TEXT, evidence TEXT,'+
  'started_at TEXT NOT NULL, updated_at TEXT NOT NULL, last_reason TEXT)');
}
export function startCanary(db,{jobId,baseSha,now=new Date().toISOString()}){
 if(jobId!==CANARY_JOB_ID||!SHA.test(baseSha))throw Error('unauthorized canary');
 ensureCanaryTable(db);
 const r=db.prepare("INSERT OR IGNORE INTO ai_github_canary(job_id,phase,base_sha,started_at,updated_at) VALUES(?,'started',?,?,?)").run(jobId,baseSha,now,now);
 if(r.changes!==1)throw Error('canary replay denied');
 return true;
}
export function advanceCanary(db,{from,to,headSha,prNumber,mergeSha,evidence,now=new Date().toISOString()}){
 if(!stages.includes(from)||!stages.includes(to)||stages.indexOf(to)!==stages.indexOf(from)+1)
  throw Error('unauthorized canary transition');
 if(headSha!==undefined&&!SHA.test(headSha))throw Error('invalid HEAD');
 if(mergeSha!==undefined&&!SHA.test(mergeSha))throw Error('invalid merge SHA');
 if(prNumber!==undefined&&(!Number.isSafeInteger(prNumber)||prNumber<1))throw Error('invalid PR number');
 if(evidence!==undefined&&(typeof evidence!=='string'||!/^[a-zA-Z0-9_.:/-]{3,255}$/.test(evidence)))
  throw Error('invalid evidence');
 ensureCanaryTable(db);
 const r=db.prepare('UPDATE ai_github_canary SET phase=?,head_sha=COALESCE(?,head_sha),'+
  'pr_number=COALESCE(?,pr_number),merge_sha=COALESCE(?,merge_sha),'+
  'evidence=COALESCE(?,evidence),updated_at=? WHERE job_id=? AND phase=?')
  .run(to,headSha??null,prNumber??null,mergeSha??null,evidence??null,now,CANARY_JOB_ID,from);
 if(r.changes!==1)throw Error('stale or replayed canary transition');
}
export function blockCanary(db,{phase,reason,uncertain=false}){
 if(typeof reason!=='string'||!/^[a-z][a-z0-9_]{2,63}$/.test(reason))throw Error('invalid failure reason');
 ensureCanaryTable(db);
 const state=uncertain?'unknown':'blocked';
 const r=db.prepare('UPDATE ai_github_canary SET phase=?,last_reason=?,updated_at=? WHERE job_id=? AND phase=?')
  .run(state,reason,new Date().toISOString(),CANARY_JOB_ID,phase);
 return r.changes===1;
}
