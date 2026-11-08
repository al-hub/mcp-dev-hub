// #36: authenticated, read-only GitHub Issue snapshot adapter.
// No polling, execution, policy issuance, GitHub mutation, or retry authority.
import {buildIssueIntakeCandidate} from './issue-intake-candidate.mjs';
import {recordIssueIntakeCandidate} from './issue-intake-ledger.mjs';

const REPO='al-hub/mcp-dev-hub';
const ORIGIN='https://api.github.com';
const PREFIX=ORIGIN+'/repos/'+REPO;
const MAX_BYTES=65536;
const deny=()=>{throw Error('live_issue_snapshot_unavailable');};

async function readBoundedJson(response){
 if(response.status!==200||!response.body||
    !String(response.headers?.get('content-type')||'').toLowerCase().includes('application/json'))deny();
 const length=Number(response.headers.get('content-length'));
 if(Number.isFinite(length)&&length>MAX_BYTES)deny();
 const reader=response.body.getReader();
 const chunks=[];let bytes=0;
 try{
  for(;;){
   const {value,done}=await reader.read();
   if(done)break;
   if(!(value instanceof Uint8Array))deny();
   bytes+=value.byteLength;
   if(bytes>MAX_BYTES)deny();
   chunks.push(value);
  }
 }catch{deny();}
 finally{reader.releaseLock();}
 try{return JSON.parse(Buffer.concat(chunks,bytes).toString('utf8'));}
 catch{deny();}
}

export async function readGitHubIssueSnapshot({
 issueNumber,tokenProvider,fetchImpl=fetch
}={}){
 if(!Number.isSafeInteger(issueNumber)||issueNumber<=0||
    typeof tokenProvider!=='function'||typeof fetchImpl!=='function')deny();
 const token=await tokenProvider();
 if(typeof token!=='string'||token.length<20||
    !/^[A-Za-z0-9_-]+$/.test(token))deny();
 const url=PREFIX+'/issues/'+issueNumber;
 let response;
 try{
  response=await fetchImpl(url,{
   method:'GET',redirect:'error',cache:'no-store',
   headers:{Accept:'application/vnd.github+json',
    'X-GitHub-Api-Version':'2022-11-28',
    Authorization:'Bearer '+token},
   signal:AbortSignal.timeout(10000)
  });
 }catch{deny();}
 if(response?.url&&response.url!==url)deny();
 const raw=await readBoundedJson(response);
 if(!raw||typeof raw!=='object'||Array.isArray(raw)||
    raw.url!==url||raw.repository_url!==PREFIX||
    raw.number!==issueNumber||
    !Number.isSafeInteger(raw.id)||raw.id<=0||
    raw.state!=='open'||Object.hasOwn(raw,'pull_request')||
    typeof raw.title!=='string'||raw.title.length<1||raw.title.length>200||
    (raw.body!==null&&typeof raw.body!=='string')||
    typeof raw.updated_at!=='string')deny();
 // The response is authenticated transport data, not execution authority.
 return Object.freeze({
  id:raw.id,number:raw.number,state:raw.state,
  repositoryFullName:REPO,title:raw.title,body:raw.body??'',
  updatedAt:raw.updated_at
 });
}

export async function buildCandidateFromLiveGitHub({
 issueNumber,policy,verifyPolicy,tokenProvider,fetchImpl=fetch,nowMs=Date.now()
}={}){
 // Never issue an authenticated outbound GET until the independently
 // supplied policy verifier and exact requested scope have passed.
 if(typeof verifyPolicy!=='function'||!policy||typeof policy!=='object'||
    Array.isArray(policy)||policy.version!==1||policy.repository!==REPO||
    !Number.isSafeInteger(issueNumber)||issueNumber<1||
    policy.issueNumber!==issueNumber||!Number.isSafeInteger(nowMs)||nowMs<0||
    !Number.isSafeInteger(policy.expiresAtMs)||
    policy.expiresAtMs<=Math.max(nowMs,Date.now())||
    policy.expiresAtMs>nowMs+86400000)deny();
 try{if(verifyPolicy(policy)!==true)deny();}catch{deny();}
 const issue=await readGitHubIssueSnapshot({issueNumber,tokenProvider,fetchImpl});
 // Network/credential access may outlive a short-lived policy. Recheck the
 // real clock after the GET; a caller's old nowMs cannot extend authority.
 const admissionNowMs=Math.max(nowMs,Date.now());
 if(policy.expiresAtMs<=admissionNowMs)deny();
 return buildIssueIntakeCandidate({
  issue,policy,verifyPolicy,
  verifyLiveIssue:current=>current===issue,
  nowMs:admissionNowMs
 });
}

/**
 * Persist one independently policy-verified, live GitHub Issue snapshot as a
 * non-executable intake candidate. This is a single bounded read, NOT a poll
 * loop or a Worker job; the caller supplies an external trusted policy verifier.
 * On network/429/uncertain outcomes it throws without retrying or recording
 * any authorization. Exact duplicate admission is idempotent in the ledger.
 */
export async function recordLiveGitHubIssueCandidate({
 db,issueNumber,policy,verifyPolicy,tokenProvider,fetchImpl=fetch,
 nowMs=Date.now()
}={}){
 if(!db||typeof db.exec!=='function'||typeof db.prepare!=='function'||
    !Number.isSafeInteger(nowMs)||nowMs<0)deny();
 const candidate=await buildCandidateFromLiveGitHub({
  issueNumber,policy,verifyPolicy,tokenProvider,fetchImpl,nowMs
 });
 return recordIssueIntakeCandidate(db,candidate,{
  at:new Date(nowMs).toISOString()
 });
}
