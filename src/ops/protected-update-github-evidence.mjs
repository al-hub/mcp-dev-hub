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
     run.path!=='.github/workflows/ci.yml'||
     run.workflow_id!==402358309||
     run.event!=='pull_request'||run.status!=='completed'||
     run.conclusion!=='success'||run.head_sha!==head||
     run.repository?.full_name!==REPO||
     !Array.isArray(run.pull_requests)||
     !run.pull_requests.some(p=>p?.number===prNumber&&
       p.head?.sha===head&&p.base?.sha===base))fail();
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

/** Verify the ACTUAL GitHub review API, not PR body text, a Worker
 * assertion, or a Codex CLI exit status. The official reviewer bot ID must
 * be pinned by the root administrator outside the repository.
 * A bot approval alone does not prove model independence; the separately
 * held Ed25519 reviewer signature is still mandatory.
 */
export function validateOfficialReviewerApproval({
  reviews,head,prNumber,reviewerBotId,nowMs
}={}){
  if(!Array.isArray(reviews)||reviews.length===0||reviews.length>=100||
     typeof head!=='string'||!SHA.test(head)||
     !Number.isSafeInteger(prNumber)||prNumber<1||
     !Number.isSafeInteger(reviewerBotId)||reviewerBotId<=0||
     !Number.isSafeInteger(nowMs)||nowMs<=0)fail();
  const selected=reviews.filter(r=>r&&r.user?.id===reviewerBotId);
  if(selected.length===0)fail();
  const parsed=selected.map(r=>{
    if(!Number.isSafeInteger(r.id)||r.id<=0||
       r.user?.type!=='Bot'||typeof r.user.login!=='string'||
       !/^[a-zA-Z0-9_-]+\[bot\]$/.test(r.user.login)||
       typeof r.submitted_at!=='string')fail();
    const t=Date.parse(r.submitted_at);
    if(!Number.isFinite(t)||t>nowMs||t<nowMs-7*86400000)
      fail();
    if(r.pull_request_url!==
       'https://api.github.com/repos/al-hub/mcp-dev-hub/pulls/'+
         prNumber)fail();
    return {review:r,t};
  });
  parsed.sort((a,b)=>a.t-b.t||a.review.id-b.review.id);
  const latest=parsed.at(-1).review;
  if(latest.state!=='APPROVED'||latest.commit_id!==head)fail();
  // Only the independently authenticated Bot can author this API field.
  // A textual evidence ID is never itself proof of actual Codex execution;
  // the trusted App publisher must validate the real Codex receipt first.
  const receipt=typeof latest.body==='string'
    ? /^AI-assisted independent Codex technical review \(not a human review\)\. Evidence: (verified-[a-z0-9-]{6,100})$/.exec(latest.body)
    : null;
  return Object.freeze({
    state:'official_github_bot_review_confirmed',
    prNumber,head,reviewerBotId,reviewId:latest.id,
    reviewActor:latest.user.login,
    reviewEvidenceId:receipt?.[1]??null,
    signerProvenanceVerified:false
  });
}
export async function fetchAndVerifyOfficialReviewerApproval({
  head,prNumber,reviewerBotId,githubToken,nowMs
}={}){
  if(!Number.isSafeInteger(prNumber)||prNumber<1||
     !Number.isSafeInteger(reviewerBotId)||reviewerBotId<1||
     typeof head!=='string'||!SHA.test(head))fail();
  const reviews=await githubGet('/repos/al-hub/mcp-dev-hub/pulls/'+
    prNumber+'/reviews?per_page=100',githubToken);
  return validateOfficialReviewerApproval({
    reviews,head,prNumber,reviewerBotId,nowMs
  });
}

async function githubGet(path,token,maxBytes=262144) {
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
        if(size>maxBytes){
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

/**
 * Read-only fixed GitHub HTTPS cross-check for a signed one-shot bootstrap.
 * The caller MUST also verify independently signed Codex review + approval,
 * root-owned issuer policy, exact source pack and pinned original baseline.
 * This never installs, merges, changes GitHub or authorizes sudo.
 */
export async function fetchAndVerifyGitHubBootstrapEvidence({
  prNumber,head,base,ciRunId,githubToken
}={}){
  if(!Number.isSafeInteger(prNumber)||prNumber<1||
     !Number.isSafeInteger(ciRunId)||ciRunId<1||
     typeof head!=='string'||!SHA.test(head)||
     typeof base!=='string'||!SHA.test(base)||head===base)fail();
  const stem='/repos/al-hub/mcp-dev-hub';
  const [pr,run,jobs,protection]=await Promise.all([
    githubGet(stem+'/pulls/'+prNumber,githubToken),
    githubGet(stem+'/actions/runs/'+ciRunId,githubToken),
    githubGet(stem+'/actions/runs/'+ciRunId+'/jobs?per_page=100',githubToken),
    githubGet(stem+'/branches/main/protection',githubToken)
  ]);
  return validateGitHubEvidenceShape({
    pr,run,jobs,protection,prNumber,head,base,ciRunId
  });
}

const FILEPATHS=Object.freeze({
  'ai-github-canary-policy.mjs':'src/jobs/ai-github-canary-policy.mjs',
  'ai-github-canary.mjs':'scripts/ai-github-canary.mjs'
});
const MAX_FILE_BYTES=256*1024;

/** Pure parsing of an authenticated fixed GitHub Contents response.
 * Caller MUST compare against a manifest authenticated by the independently
 * pinned approval signer. This helper alone grants no authority.
 */
export function validateGitHubControllerSource(blob,{
  name,head,bytes,sha256
}={}){
  if(typeof name!=='string'||!Object.hasOwn(FILEPATHS,name)||
     typeof head!=='string'||!SHA.test(head)||
     !Number.isSafeInteger(bytes)||bytes<1||bytes>MAX_FILE_BYTES||
     typeof sha256!=='string'||!HASH.test(sha256))fail();
  const expectedPath=FILEPATHS[name];
  if(blob?.type!=='file'||blob.path!==expectedPath||
     blob.name!==expectedPath.split('/').at(-1)||
     blob.encoding!=='base64'||blob.size!==bytes||
     typeof blob.sha!=='string'||!SHA.test(blob.sha)||
     typeof blob.content!=='string')fail();
  const encoded=blob.content.replace(/\r?\n/g,'');
  if(!/^[a-zA-Z0-9+/]+={0,2}$/.test(encoded))fail();
  const data=Buffer.from(encoded,'base64');
  if(data.length!==bytes||data.toString('base64')!==encoded||
     createHash('sha256').update(data).digest('hex')!==sha256)fail();
  return data;
}

/** Obtain the exact fixed controller-pair source from GitHub TLS, never
 * arbitrary caller paths or content. This is a candidate root-side fetcher,
 * not a deployable root updater or proof of the signer trust bootstrap.
 */
export async function fetchAndVerifyGitHubControllerPair({
  head,manifestFiles,githubToken
}={}){
  if(typeof head!=='string'||!SHA.test(head)||
     !Array.isArray(manifestFiles)||manifestFiles.length!==2||
     new Set(manifestFiles.map(f=>f?.name)).size!==2||
     !Object.keys(FILEPATHS).every(name=>
       manifestFiles.some(f=>f?.name===name)))fail();
  const stem='/repos/al-hub/mcp-dev-hub';
  const result=Object.create(null);
  for(const name of Object.keys(FILEPATHS)){
    const f=manifestFiles.find(file=>file.name===name);
    // All untrusted fields are validated before any transport invocation.
    if(!Number.isSafeInteger(f.bytes)||f.bytes<1||
       f.bytes>MAX_FILE_BYTES||typeof f.sha256!=='string'||
       !HASH.test(f.sha256))fail();
  }
  // These paths and hostname are literal, not drawn from PR/Issue text.
  const rows=await Promise.all(Object.entries(FILEPATHS).map(
    async ([name,sourcePath])=>{
      const blob=await githubGet(
        stem+'/contents/'+sourcePath+'?ref='+head,githubToken,500000);
      const f=manifestFiles.find(file=>file.name===name);
      return [name,validateGitHubControllerSource(blob,{...f,head})];
    }
  ));
  for(const [name,bytes] of rows)result[name]=bytes;
  return result;
}
