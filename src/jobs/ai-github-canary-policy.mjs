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
export function canaryAuthorized({job,scope,write,push,enabled,approvedId}={}){
 return job?.id===CANARY_JOB_ID&&job.kind==='ai-github-canary'&&
   ['queued','starting','running'].includes(job.state)&&
   job.target==='local'&&[job.project,job.target,job.workspace].join(':')===scope&&
   write==='0'&&push==='0'&&enabled==='1'&&approvedId===CANARY_JOB_ID;
}
// The model returns DATA ONLY; source code is constructed exclusively from a
// reviewed local template. No model-supplied JavaScript is ever executed.
export function validateCandidate(source){
 let item;
 try{item=JSON.parse(source);}catch{return false;}
 if(!item||typeof item!=='object'||Array.isArray(item))return false;
 const keys=Object.keys(item).sort();
 if(keys.join(',')!=='token23,token24')return false;
 return typeof item.token24==='string'&&typeof item.token23==='string'&&
  /^sample-public-[a-z]{10}$/.test(item.token24)&&
  /^sample-public-[a-z]{9}$/.test(item.token23);
}
export function renderCandidate(source){
 if(!validateCandidate(source))throw Error('candidate_rejected');
 const {token24,token23}=JSON.parse(source);
 return [
  "import test from 'node:test';",
  "import assert from 'node:assert/strict';",
  "import {safeBearer} from '../src/dashboard/read-only-server.mjs';",
  'const valid='+JSON.stringify(token24)+';',
  'const short='+JSON.stringify(token23)+';',
  "test('minimum 24-character public bearer token acceptance and 23 rejection',()=>{",
  ' assert.equal(valid.length,24);',
  ' assert.equal(short.length,23);',
  " assert.equal(safeBearer('Bearer '+valid,valid),true);",
  " assert.equal(safeBearer('Bearer '+short,short),false);",
  " assert.equal(safeBearer('bearer '+valid,valid),false);",
  " assert.equal(safeBearer('Bearer '+short,valid),false);",
  '});',
  ''
 ].join('\n');
}
// Independent reviewer must supply an unambiguous exact-HEAD approval.
// Prefix matches, prose around JSON, duplicate keys and conditional passes fail closed.
export function validateReviewVerdict(raw,{head,base}={}){
 if(typeof raw!=='string'||raw.length<80||raw.length>6500||
   raw.includes('\\')||!SHA.test(head||'')||!SHA.test(base||''))return false;
 for(const key of ['verdict','head','base','findings']){
  if((raw.match(new RegExp('"'+key+'"\\s*:','g'))||[]).length!==1)return false;
 }
 let data;
 try{data=JSON.parse(raw);}catch{return false;}
 if(!data||typeof data!=='object'||Array.isArray(data)||
   Object.keys(data).sort().join(',')!=='base,findings,head,verdict')return false;
 return data.verdict==='PASS'&&data.head===head&&data.base===base&&
   Array.isArray(data.findings)&&data.findings.length===0;
}
// Server-side invariant: strict required CI rejects stale PR heads at merge
// time, including when main advances after our last read. Admins may not bypass.
export function verifiedStrictGitHubProtection(p){
 const checks=p?.required_status_checks;
 return checks?.strict===true&&
  Array.isArray(checks?.contexts)&&checks.contexts.includes('bootstrap')&&
  Array.isArray(checks?.checks)&&
  checks.checks.some(row=>row.context==='bootstrap'&&row.app_id===15368)&&
  p?.enforce_admins?.enabled===true&&
  p?.allow_force_pushes?.enabled===false;
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
