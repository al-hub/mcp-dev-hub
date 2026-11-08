// #36: untrusted GitHub Issue -> bounded, non-executable intake candidate.
// This code deliberately grants NO Agent, git, GitHub or OS write authority.
// The caller must independently authenticate the policy and live Issue snapshot.
import {createHash} from 'node:crypto';

const REPO='al-hub/mcp-dev-hub';
const SHA=/^[a-f0-9]{40}$/;
const DIGEST=/^[a-f0-9]{64}$/;
const SCOPE=/^[a-z][a-z0-9_-]{2,47}$/;
const PATH=/^(?:src|tests|docs)\/[A-Za-z0-9._/-]{1,160}$/;
const denied=()=>{throw Error('untrusted_or_out_of_scope_issue');};

export function safeIssuePath(path){
 if(typeof path!=='string'||!PATH.test(path)||path.length>180||
    path.includes('\\')||path.endsWith('/')||path.includes('//')||
    path.split('/').some(x=>x==='.'||x==='..'||x.startsWith('.'))||
    /(?:^|\/)(?:protected-update|reviewer-app|github-app-review-publisher)/.test(path))
  return false;
 return true;
}

export function buildIssueIntakeCandidate({
 issue,policy,verifyPolicy,verifyLiveIssue,nowMs=Date.now()
}={}){
 // A raw Issue body, labels, or AI suggestion can never self-authorize work.
 if(typeof verifyPolicy!=='function'||typeof verifyLiveIssue!=='function'||
    !Number.isSafeInteger(nowMs)||nowMs<0)denied();
 if(!issue||!policy||typeof issue!=='object'||typeof policy!=='object'||
    Array.isArray(issue)||Array.isArray(policy))denied();
 const validIssue=Number.isSafeInteger(issue.id)&&issue.id>0&&
    Number.isSafeInteger(issue.number)&&issue.number>0&&
    issue.state==='open'&&!Object.hasOwn(issue,'pull_request')&&
    issue.repositoryFullName===REPO&&
    typeof issue.title==='string'&&issue.title.length>=1&&issue.title.length<=200&&
    typeof issue.body==='string'&&Buffer.byteLength(issue.body,'utf8')<=8192&&
    !/[\x00-\x08\x0b\x0c\x0e-\x1f]/.test(issue.body)&&
    typeof issue.updatedAt==='string'&&
    Number.isFinite(Date.parse(issue.updatedAt))&&
    /^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(?:\\.\\d{1,3})?Z$/.test(issue.updatedAt);
 if(!validIssue)denied();
 const validPolicy=policy.version===1&&policy.repository===REPO&&
    policy.issueId===issue.id&&policy.issueNumber===issue.number&&
    policy.issueUpdatedAt===issue.updatedAt&&
    SHA.test(policy.baseSha||'')&&DIGEST.test(policy.policyDigest||'')&&
    SCOPE.test(policy.scopeId||'')&&
    Number.isSafeInteger(policy.expiresAtMs)&&
    policy.expiresAtMs>nowMs&&policy.expiresAtMs<=nowMs+86400000&&
    Array.isArray(policy.allowedFiles)&&policy.allowedFiles.length>0&&
    policy.allowedFiles.length<=20&&
    policy.allowedFiles.every(safeIssuePath)&&
    new Set(policy.allowedFiles).size===policy.allowedFiles.length;
 if(!validPolicy)denied();
 // Policy and observed issue identity are independently attested by trusted
 // callers; these callbacks must never be derived from Issue or model text.
 if(verifyPolicy(policy)!==true||verifyLiveIssue(issue)!==true)denied();
 const files=Object.freeze([...policy.allowedFiles].sort());
 const candidateId=createHash('sha256').update(JSON.stringify({
    repository:REPO,issueId:issue.id,issueNumber:issue.number,
    updatedAt:issue.updatedAt,scopeId:policy.scopeId,
    baseSha:policy.baseSha,policyDigest:policy.policyDigest,files
 })).digest('hex');
 return Object.freeze({
   kind:'issue-intake-candidate-v1',status:'candidate_only',
   repository:REPO,issueId:issue.id,issueNumber:issue.number,
   issueUpdatedAt:issue.updatedAt,baseSha:policy.baseSha,
   scopeId:policy.scopeId,policyDigest:policy.policyDigest,
   candidateId,allowedFiles:files,
   // Later isolated Worker and independent review must add their OWN gates.
   executionAuthorized:false,githubWriteAuthorized:false,rootAuthorized:false
 });
}

export function pathMatchesIssueCandidate(candidate,path){
 return candidate?.kind==='issue-intake-candidate-v1'&&
   candidate.status==='candidate_only'&&
   candidate.executionAuthorized===false&&
   Array.isArray(candidate.allowedFiles)&&
   safeIssuePath(path)&&candidate.allowedFiles.includes(path);
}
