// #35: candidate live GitHub + independent signed-review evidence gate.
// This is NOT installed as a root updater and grants no OS authority.
// The immutable root adapter must pin caller identity, reviewer/approval public
// keys and HTTPS trust; it must never take tokens or keys from Issue/PR content.
import {createHash,createPublicKey,verify} from 'node:crypto';
import {request} from 'node:https';

const REPO='al-hub/mcp-dev-hub';
const SHA=/^[a-f0-9]{40}$/;
const HASH=/^[a-f0-9]{64}$/;
const UUID=/^[a-f0-9]{32}$/;
const B64=/^[A-Za-z0-9+/]{86}==$/;
const REVIEW_FIELDS=Object.freeze([
  'version','repository','prNumber','head','base','reviewer',
  'reviewRunId','reviewVerdict','findings','issuedAtMs','expiresAtMs'
]);
const DOMAIN='mcp-dev-hub/independent-codex-review/v1\n';
const fail=()=>{throw Error('protected_evidence_denied');};
const exact=(o,k)=>o!==null&&typeof o==='object'&&
  !Array.isArray(o)&&Object.keys(o).length===k.length&&
  k.every(x=>Object.hasOwn(o,x));
const sha256=s=>createHash('sha256').update(s,'utf8').digest('hex');

export function verifyIndependentSignedReview({
  reviewJson,signatureBase64,pinnedReviewerPublicKeyPem,
  pinnedApprovalPublicKeyPem,head,base,prNumber,nowMs
}={}){
  if(typeof reviewJson!=='string'||Buffer.byteLength(reviewJson,'utf8')>2048||
     typeof signatureBase64!=='string'||!B64.test(signatureBase64)||
     typeof head!=='string'||!SHA.test(head)||
     typeof base!=='string'||!SHA.test(base)||head===base||
     !Number.isSafeInteger(prNumber)||prNumber<1||
     !Number.isSafeInteger(nowMs)||nowMs<1)fail();
  let r;
  try{r=JSON.parse(reviewJson);}catch{fail();}
  if(!exact(r,REVIEW_FIELDS)||JSON.stringify(r)!==reviewJson||
     r.version!==1||r.repository!==REPO||r.prNumber!==prNumber||
     r.head!==head||r.base!==base||
     r.reviewer!=='independent-codex'||
     typeof r.reviewRunId!=='string'||!UUID.test(r.reviewRunId)||
     r.reviewVerdict!=='PASS'||!Array.isArray(r.findings)||
     r.findings.length!==0||
     !Number.isSafeInteger(r.issuedAtMs)||
     !Number.isSafeInteger(r.expiresAtMs)||
     r.issuedAtMs>nowMs||r.expiresAtMs<nowMs||
     r.expiresAtMs<=r.issuedAtMs||
     r.expiresAtMs-r.issuedAtMs>600000)fail();
  let reviewer,approval;
  try{
    reviewer=createPublicKey(pinnedReviewerPublicKeyPem);
    approval=createPublicKey(pinnedApprovalPublicKeyPem);
  }catch{fail();}
  if(reviewer.asymmetricKeyType!=='ed25519'||
     approval.asymmetricKeyType!=='ed25519')fail();
  // Review and updater approval must never be the same signing principal.
  if(reviewer.export({type:'spki',format:'der'}).equals(
       approval.export({type:'spki',format:'der'})))fail();
  const sig=Buffer.from(signatureBase64,'base64');
  if(sig.length!==64||sig.toString('base64')!==signatureBase64||
     !verify(null,Buffer.from(DOMAIN+reviewJson,'utf8'),reviewer,sig))fail();
  return Object.freeze({
    head:r.head,base:r.base,prNumber:r.prNumber,
    reviewDigest:sha256(reviewJson),reviewRunId:r.reviewRunId
  });
}
export const INDEPENDENT_REVIEW_DOMAIN=DOMAIN;

// Only call with objects obtained by the immutable root HTTPS client below.
// This *pure* shape check by itself authenticates NOTHING and is never a
// production authorization token. It is exported solely for synthetic tests.
export function validateGitHubEvidenceShape({
  pr,run,jobs,protection,prNumber,head,base,ciRunId
}={}){
  if(!Number.isSafeInteger(prNumber)||prNumber<1||
     !Number.isSafeInteger(ciRunId)||ciRunId<1||
     typeof head!=='string'||!SHA.test(head)||
     typeof base!=='string'||!SHA.test(base)||head===base)fail();
  if(pr?.number!==prNumber||pr.state!=='open'||pr.draft!==false||
     pr.head?.sha!==head||pr.head?.repo?.full_name!==REPO||
     pr.base?.sha!==base||pr.base?.ref!=='main'||
     pr.base?.repo?.full_name!==REPO)fail();
  if(run?.id!==ciRunId||run.name!=='CI'||
     run.event!=='pull_request'||run.status!=='completed'||
     run.conclusion!=='success'||run.head_sha!==head||
     run.repository?.full_name!==REPO||
     !Array.isArray(run.pull_requests)||
     !run.pull_requests.some(p=>p?.number===prNumber))fail();
  if(!Array.isArray(jobs?.jobs)||jobs.jobs.length<1||
     jobs.total_count!==jobs.jobs.length||
     jobs.jobs.filter(j=>j?.name==='bootstrap'&&
       j.status==='completed'&&j.conclusion==='success'&&
       Array.isArray(j.steps)&&j.steps.some(step=>
         step.name==='Run npm run check'&&step.conclusion==='success')
     ).length!==1)fail();
  const checks=protection?.required_status_checks;
  if(checks?.strict!==true||
     !Array.isArray(checks.contexts)||
     !checks.contexts.includes('bootstrap')||
     !Array.isArray(checks.checks)||
     !checks.checks.some(c=>c?.context==='bootstrap'&&
       c.app_id===15368)||
     protection?.enforce_admins?.enabled!==true||
     protection?.allow_force_pushes?.enabled!==false||
     protection?.allow_deletions?.enabled!==false||
     protection?.required_conversation_resolution?.enabled!==true)fail();
  return Object.freeze({
    head,base,ciRunId,ciHead:head,ciPassed:true,strictProtection:true
  });
}

async function githubGet(path,token) {
  if(typeof token!=='string'||token.length<8||token.length>4096||
     /[\r\n\t ]/.test(token)||typeof path!=='string'||
     !/^\/repos\/al-hub\/mcp-dev-hub\//.test(path))fail();
  return await new Promise((resolve,reject)=>{
    const req=request({
      hostname:'api.github.com',port:443,protocol:'https:',
      method:'GET',path,timeout:10000,
      headers:{
        Accept:'application/vnd.github+json',
        Authorization:'Bearer '+token,
        'X-GitHub-Api-Version':'2022-11-28',
        'User-Agent':'mcp-dev-hub-protected-evidence/1'
      }
    },res=>{
      if(res.statusCode!==200||
         !String(res.headers['content-type']||'')
           .toLowerCase().includes('application/json')){
        res.resume();reject(Error('protected_evidence_denied'));return;
      }
      let size=0;
      const chunks=[];
      res.on('data',chunk=>{
        size+=chunk.length;
        if(size>262144){
          req.destroy(Error('protected_evidence_denied'));return;
        }
        chunks.push(chunk);
      });
      res.on('end',()=>{
        try{resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));}
        catch{reject(Error('protected_evidence_denied'));}
      });
      res.on('error',()=>reject(Error('protected_evidence_denied')));
    });
    req.on('timeout',()=>req.destroy(Error('protected_evidence_denied')));
    req.on('error',()=>reject(Error('protected_evidence_denied')));
    req.end();
  });
}
/**
 * Root-supervisor-only candidate: fetch fixed GitHub REST endpoints over TLS
 * and independently verify a separately signed Codex review. A fail-closed
 * shape is returned; callers must still authenticate root-owned policy, key
 * provenance, exact contents and anti-replay journal before privileged acts.
 */
export async function fetchAndVerifyGitHubUpdateEvidence({
  prNumber,head,base,ciRunId,githubToken,
  reviewJson,reviewSignatureBase64,
  pinnedReviewerPublicKeyPem,pinnedApprovalPublicKeyPem,nowMs
}={}){
  // Reject untrusted identifiers BEFORE any token-backed network access.
  if(!Number.isSafeInteger(prNumber)||prNumber<1||
     !Number.isSafeInteger(ciRunId)||ciRunId<1||
     typeof head!=='string'||!SHA.test(head)||
     typeof base!=='string'||!SHA.test(base)||head===base)fail();
  const review=verifyIndependentSignedReview({
    reviewJson,signatureBase64:reviewSignatureBase64,
    pinnedReviewerPublicKeyPem,pinnedApprovalPublicKeyPem,
    head,base,prNumber,nowMs
  });
  const stem='/repos/al-hub/mcp-dev-hub';
  // No redirects, query URL or hostname is supplied by any Issue/Worker.
  const [pr,run,jobs,protection]=await Promise.all([
    githubGet(stem+'/pulls/'+prNumber,githubToken),
    githubGet(stem+'/actions/runs/'+ciRunId,githubToken),
    githubGet(stem+'/actions/runs/'+ciRunId+'/jobs?per_page=100',githubToken),
    githubGet(stem+'/branches/main/protection',githubToken)
  ]);
  const gh=validateGitHubEvidenceShape({
    pr,run,jobs,protection,prNumber,head,base,ciRunId
  });
  return Object.freeze({
    ...gh,independentReviewPassed:true,
    reviewHead:review.head,reviewBase:review.base,
    reviewDigest:review.reviewDigest
  });
}
