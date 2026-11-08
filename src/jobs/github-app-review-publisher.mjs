import {createSign} from 'node:crypto';
import {lstatSync,readFileSync,realpathSync} from 'node:fs';
import {verifyIndependentSignedReview}
  from '../ops/protected-update-github-evidence.mjs';
import {deriveSignedCodexEvidenceId}
  from '../ops/protected-update-bootstrap-issuer.mjs';

// GitHub App publisher for one explicitly authorized repository.
// AI output is never an approval by itself. The caller must supply a trusted
// Worker evidence verifier and an independently authenticated App client.
const SHA=/^[a-f0-9]{40}$/;
const REPO='al-hub/mcp-dev-hub';
const GATES=['ci','security','private_sse','pc','galaxy'];
// #35 keeps all existing gates and requires additional privileged checks.
const PROTECTED_BOOTSTRAP_GATES=['root_security','original_restore'];
const PR_ALLOWLIST=Object.freeze([17,39]);
const fail=(message)=>{throw Error(message);};
export function validateReviewEvidence({
 headSha,evidence,verifyEvidence,prNumber=17,baseSha,
 signedCodexReceipt,pinnedCodexPublicKeyPem,pinnedIssuerReviewerPublicKeyPem,
 packDigest
}){
 if(!PR_ALLOWLIST.includes(prNumber))fail('review PR outside fixed scope');
 if(!SHA.test(headSha)||typeof verifyEvidence!=='function')fail('trusted evidence verifier required');
 if(!evidence||evidence.headSha!==headSha||evidence.authorAgent!=='agy'||
   evidence.reviewerAgent!=='codex'||evidence.verdict!=='passed'||
   evidence.reviewReadonly!==true||evidence.reviewIsolated!==true||
   evidence.exitCode!==0||typeof evidence.evidenceId!=='string'||
   !/^verified-[a-z0-9-]{6,100}$/.test(evidence.evidenceId))fail('independent review evidence unavailable');
 for(const gate of GATES){
  const value=evidence.gates?.[gate];
  if(value?.headSha!==headSha||value?.verdict!=='passed'||
     typeof value?.evidenceId!=='string'||value.evidenceId.length<4)fail('acceptance gate incomplete');
 }
 if(prNumber===39){
  if(evidence.scope!=='protected-bootstrap'||
     evidence.prNumber!==39)fail('protected bootstrap evidence scope denied');
  // Verify the actual independent signature BEFORE any GitHub App API call.
  // The public keys and package digest MUST be pinned out of band by the
  // separately installed trusted publisher, never sourced from PR text.
  if(!SHA.test(baseSha||'')||baseSha===headSha||
     typeof signedCodexReceipt?.reviewJson!=='string'||
     typeof signedCodexReceipt?.signatureBase64!=='string'||
     typeof pinnedCodexPublicKeyPem!=='string'||
     typeof pinnedIssuerReviewerPublicKeyPem!=='string')
   fail('independent signed Codex receipt unavailable');
  let signed;
  try{
   signed=verifyIndependentSignedReview({
    reviewJson:signedCodexReceipt.reviewJson,
    signatureBase64:signedCodexReceipt.signatureBase64,
    pinnedReviewerPublicKeyPem:pinnedCodexPublicKeyPem,
    pinnedApprovalPublicKeyPem:pinnedIssuerReviewerPublicKeyPem,
    head:headSha,base:baseSha,prNumber:39,nowMs:Date.now()
   });
  }catch{
   fail('independent signed Codex receipt invalid');
  }
  let expectedEvidenceId;
  try{expectedEvidenceId=deriveSignedCodexEvidenceId({
   reviewDigest:signed.reviewDigest,packDigest
  });}catch{fail('independent Codex package digest invalid');}
  if(evidence.evidenceId!==expectedEvidenceId)
   fail('independent Codex evidence ID mismatch');
  for(const gate of PROTECTED_BOOTSTRAP_GATES){
   const value=evidence.gates?.[gate];
   if(value?.headSha!==headSha||value?.verdict!=='passed'||
      typeof value?.evidenceId!=='string'||
      !/^verified-[a-z0-9-]{6,100}$/.test(value.evidenceId))
    fail('privileged security and recovery gate incomplete');
  }
 }
 return verifyEvidence(evidence)===true || fail('unverified independent review provenance');
}
// Protection information comes from a separately trusted verifier; this
// narrowly scoped review App must never gain policy/contents permissions.
// Both the evidence and its provenance must be pinned to the exact PR HEAD.
export function validateProtectionEvidence({headSha,protectionEvidence,verifyProtectionEvidence,prNumber=17}){
 const p=protectionEvidence;
 if(typeof verifyProtectionEvidence!=='function'||!p||p.repository!==REPO||
    p.branch!=='main'||p.headSha!==headSha||p.enforceAdmins!==true||
    p.requireConversationResolution!==true||!Array.isArray(p.requiredChecks)||
    !p.requiredChecks.includes('bootstrap')||
    typeof p.evidenceId!=='string'||!/^verified-[a-z0-9-]{6,100}$/.test(p.evidenceId))
   fail('trusted branch protection evidence unavailable');
 // #35 is explicitly scoped to an independently verified Bot approval and
 // separately signed privilege authorization. The owner previously removed
 // repository-wide required PR reviews; never silently re-enable that rule.
 // A trusted out-of-band policy verifier MUST confirm the absent review rule.
 if(prNumber===39){
  if(p.requiredApprovals!==0||p.reviewRuleAbsent!==true)
   fail('protected bootstrap policy evidence unavailable');
 }else if(!Number.isSafeInteger(p.requiredApprovals)||
          p.requiredApprovals<1||p.dismissStaleReviews!==true||
          p.requireLastPushApproval!==true)
   fail('trusted branch protection evidence unavailable');
 if(verifyProtectionEvidence(p)!==true)fail('unverified branch protection provenance');
 return true;
}
export function createAppJwt({appId,privateKey,now=Math.floor(Date.now()/1000)}){
 if(!Number.isSafeInteger(appId)||appId<1||typeof privateKey!=='string'||!privateKey.includes('PRIVATE KEY')||
    !Number.isSafeInteger(now))fail('invalid GitHub App configuration');
 const encoded=o=>Buffer.from(JSON.stringify(o)).toString('base64url');
 const value=encoded({alg:'RS256',typ:'JWT'})+'.'+encoded({iat:now-60,exp:now+540,iss:String(appId)});
 const signature=createSign('RSA-SHA256').update(value).end().sign(privateKey,'base64url');
 return value+'.'+signature;
}
export function readPrivateKey(path){
 if(typeof path!=='string'||!path.startsWith('/')||path.includes('/../'))fail('invalid private key path');
 const st=lstatSync(path);
 if(!st.isFile()||st.isSymbolicLink()||(st.mode&0o077)!==0||
    (typeof process.getuid==='function'&&st.uid!==process.getuid()))fail('insecure private key permissions');
 const real=realpathSync(path);
 if(real!==path)fail('private key must be a direct regular file');
 return readFileSync(path,'utf8');
}
export async function createScopedAppClient({appId,installationId,repositoryId,
 key,fetchImpl=fetch,prNumber=17}){
 if(!PR_ALLOWLIST.includes(prNumber))fail('unapproved PR scope');
 if(!Number.isSafeInteger(installationId)||installationId<1||
    !Number.isSafeInteger(repositoryId)||repositoryId<1)fail('invalid App installation');
 const jwt=createAppJwt({appId,privateKey:key});
 const call=async(method,path,body,token)=>{
  const response=await fetchImpl('https://api.github.com'+path,{
   method,headers:{Accept:'application/vnd.github+json',
    Authorization:'Bearer '+token,'X-GitHub-Api-Version':'2022-11-28',
    ...(body?{'Content-Type':'application/json'}:{})},
   ...(body?{body:JSON.stringify(body)}:{}),signal:AbortSignal.timeout(12000)
  });
  if(!response.ok)fail('GitHub App request denied or unavailable');
  return response.json();
 };
 const app=await call('GET','/app',null,jwt);
 if(app.id!==appId||!/^[-a-z0-9]+$/.test(app.slug||''))fail('unexpected GitHub App identity');
 const access=await call('POST','/app/installations/'+installationId+'/access_tokens',
   {repository_ids:[repositoryId],permissions:{pull_requests:'write'}},jwt);
 if(typeof access.token!=='string'||access.token.length<20||
    access.permissions?.pull_requests!=='write')fail('insufficient scoped installation token');
 // Restrict BOTH HTTP verbs and endpoint payloads. An App installation
 // token is not authorization for a generic GraphQL mutation or PR edit.
 // Each client is bound to ONE requested PR, including review publication.
 const prPath='/repos/'+REPO+'/pulls/'+prNumber;
 const graphQuery='query($owner:String!,$name:String!,$number:Int!){repository(owner:$owner,name:$name){pullRequest(number:$number){headRefOid reviewDecision}}}';
 const exactKeys=(o,keys)=>o!==null&&typeof o==='object'&&
   !Array.isArray(o)&&Object.keys(o).length===keys.length&&
   keys.every(k=>Object.hasOwn(o,k));
 const scoped=async (method,path,body)=>{
  const get=method==='GET'&&body===undefined&&
    (path===prPath||path===prPath+'/reviews?per_page=100');
  const approve=method==='POST'&&path===prPath+'/reviews'&&
    exactKeys(body,['commit_id','event','body'])&&
    SHA.test(body.commit_id||'')&&body.event==='APPROVE'&&
    typeof body.body==='string'&&
    /^AI-assisted independent Codex technical review \\(not a human review\\). Evidence: verified-[a-z0-9-]{6,100}$/.test(body.body);
  const graph=method==='POST'&&path==='/graphql'&&
    exactKeys(body,['query','variables'])&&body.query===graphQuery&&
    exactKeys(body.variables,['owner','name','number'])&&
    body.variables.owner==='al-hub'&&
    body.variables.name==='mcp-dev-hub'&&
    body.variables.number===prNumber;
  if(!get&&!approve&&!graph)fail('unapproved GitHub App API path or payload');
  return call(method,path,body,access.token);
 };
 const repos=await scoped('GET','/repos/al-hub/mcp-dev-hub/pulls/'+prNumber);
 if(repos.base?.repo?.id!==undefined && repos.base.repo.id!==repositoryId)fail('repository identity mismatch');
 return {api:scoped,actor:app.slug+'[bot]'};
}
export async function publishIndependentApproval({
 api,actor,headSha,prNumber=17,evidence,verifyEvidence,
 protectionEvidence,verifyProtectionEvidence,baseSha,
 signedCodexReceipt,pinnedCodexPublicKeyPem,pinnedIssuerReviewerPublicKeyPem,
 packDigest
}){
 if(typeof api!=='function'||typeof actor!=='string'||!/^[-a-z0-9]+\[bot\]$/.test(actor)||
    !PR_ALLOWLIST.includes(prNumber)||!SHA.test(headSha))fail('review publisher scope denied');
 validateReviewEvidence({
  headSha,evidence,verifyEvidence,prNumber,baseSha,signedCodexReceipt,
  pinnedCodexPublicKeyPem,pinnedIssuerReviewerPublicKeyPem,packDigest
 });
 validateProtectionEvidence({headSha,protectionEvidence,verifyProtectionEvidence,prNumber});
 const prefix='/repos/'+REPO;
 const pr=await api('GET',prefix+'/pulls/'+prNumber);
 if(pr.number!==prNumber||pr.state!=='open'||pr.head?.sha!==headSha||
    pr.base?.ref!=='main'||pr.user?.login===actor||
    (prNumber===39&&pr.base?.sha!==baseSha)||
    (prNumber===39&&(pr.draft!==false||pr.base?.repo?.full_name!==REPO)))
    fail('stale, draft or self-authored pull request');
 // CI is an independently verified exact-SHA acceptance gate in
 // validateReviewEvidence. The pull_requests-only App never queries Actions.
 const reviews=await api('GET',prefix+'/pulls/'+prNumber+'/reviews?per_page=100');
 if(!Array.isArray(reviews)||reviews.length>=100)fail('incomplete GitHub reviews listing');
 const latestActorReview=(rows)=>{
  const relevant=rows.filter(x=>x.user?.login===actor &&
   ['APPROVED','CHANGES_REQUESTED','DISMISSED'].includes(x.state));
  relevant.sort((a,b)=>{
   const ta=Date.parse(a.submitted_at||''),tb=Date.parse(b.submitted_at||'');
   return Number.isFinite(ta)&&Number.isFinite(tb)?ta-tb||a.id-b.id:a.id-b.id;
  });
  return relevant.at(-1);
 };
 const own=latestActorReview(reviews);
 // An existing same-HEAD APPROVED is reusable only when it endorses the
 // precise independently verified evidence presented in THIS invocation.
 // Otherwise do not treat an unrelated Bot review as proof or POST again.
 const expectedReviewBody=
  'AI-assisted independent Codex technical review (not a human review). Evidence: '+evidence.evidenceId;
 if(own && (own.state!=='APPROVED'||own.commit_id!==headSha||
    (prNumber===39&&own.body!==expectedReviewBody)))
  fail('existing Bot review needs reconciliation');
 let review=own;
 if(!review){
  // Check the HEAD and existing Bot reviews at the last possible point before POST.
  const justBefore=await api('GET',prefix+'/pulls/'+prNumber);
  if(justBefore.number!==prNumber||justBefore.state!=='open'||
     justBefore.head?.sha!==headSha||justBefore.base?.ref!=='main'||
     (prNumber===39&&justBefore.base?.sha!==baseSha)||
     (prNumber===39&&(justBefore.draft!==false||
       justBefore.base?.repo?.full_name!==REPO)))
   fail('PR HEAD moved immediately before approval POST');
  const prePostReviews=await api('GET',prefix+'/pulls/'+prNumber+'/reviews?per_page=100');
  if(!Array.isArray(prePostReviews)||prePostReviews.length>=100||
     prePostReviews.some(x=>x.user?.login===actor))
   fail('review submission changed or incomplete; reconcile before POST');
  // Uncertain POST is never repeated. Any error needs an explicit live reconciliation.
  review=await api('POST',prefix+'/pulls/'+prNumber+'/reviews',{
   commit_id:headSha,event:'APPROVE',
   body:expectedReviewBody
  });
 }
 const after=await api('GET',prefix+'/pulls/'+prNumber+'/reviews?per_page=100');
 const effective=Array.isArray(after)&&after.length<100?latestActorReview(after):null;
 const confirmed=Number.isSafeInteger(review?.id)&&effective?.id===review.id&&
    effective.state==='APPROVED'&&effective.commit_id===headSha&&
    effective.user?.login===actor&&
    (prNumber!==39||effective.body===expectedReviewBody);
 if(!confirmed)fail('review submission not confirmed; do not retry');
 const query='query($owner:String!,$name:String!,$number:Int!){repository(owner:$owner,name:$name){pullRequest(number:$number){headRefOid reviewDecision}}}';
 const result=await api('POST','/graphql',{query,variables:{owner:'al-hub',name:'mcp-dev-hub',number:prNumber}});
 const decision=result.data?.repository?.pullRequest;
 // With no repository-wide required reviews, GitHub can report null instead
 // of APPROVED. The exact-head real Bot review was already re-read above;
 // root activation also separately validates the pinned Bot actor and review.
 if(decision?.headRefOid!==headSha||
    (prNumber===39
      ? ![null,'APPROVED'].includes(decision.reviewDecision)
      : decision.reviewDecision!=='APPROVED'))
  fail('GitHub does not confirm same-HEAD review state');
 const afterPr=await api('GET',prefix+'/pulls/'+prNumber);
 if(afterPr.number!==prNumber||afterPr.head?.sha!==headSha||
    afterPr.state!=='open'||(prNumber===39&&afterPr.base?.sha!==baseSha))
  fail('PR HEAD moved during approval confirmation');
 return {state:'approved',reviewId:review.id,reviewUrl:review.html_url??null,headSha,actor};
}
