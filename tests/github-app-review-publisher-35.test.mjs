import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign} from 'node:crypto';
import {INDEPENDENT_REVIEW_DOMAIN}
  from '../src/ops/protected-update-github-evidence.mjs';
import {deriveSignedCodexEvidenceId}
  from '../src/ops/protected-update-bootstrap-issuer.mjs';
import {createScopedAppClient,publishIndependentApproval,
  validateReviewEvidence} from '../src/jobs/github-app-review-publisher.mjs';

const HEAD='a'.repeat(40),BASE='b'.repeat(40);
const PACK='c'.repeat(64),BOT='independent-reviewer[bot]';
const codexKey=generateKeyPairSync('ed25519');
const issuerKey=generateKeyPairSync('ed25519');
const publicPem=k=>k.publicKey.export({type:'spki',format:'pem'});
const now=Date.now();
const reviewJson=JSON.stringify({
 version:1,repository:'al-hub/mcp-dev-hub',prNumber:39,
 head:HEAD,base:BASE,reviewer:'independent-codex',
 reviewRunId:'f'.repeat(32),reviewVerdict:'PASS',findings:[],
 issuedAtMs:now-1000,expiresAtMs:now+300000
});
const signedCodexReceipt={
 reviewJson,signatureBase64:sign(null,
  Buffer.from(INDEPENDENT_REVIEW_DOMAIN+reviewJson),
  codexKey.privateKey).toString('base64')
};
const EVIDENCE_ID=deriveSignedCodexEvidenceId({
 reviewDigest:(await import('node:crypto')).createHash('sha256')
  .update(reviewJson).digest('hex'),packDigest:PACK
});
const receiptArgs={
 baseSha:BASE,packDigest:PACK,signedCodexReceipt,
 pinnedCodexPublicKeyPem:publicPem(codexKey),
 pinnedIssuerReviewerPublicKeyPem:publicPem(issuerKey)
};
const VERDICT={headSha:HEAD,verdict:'passed'};
const evidence=()=>({
  headSha:HEAD,prNumber:39,scope:'protected-bootstrap',
  authorAgent:'agy',reviewerAgent:'codex',verdict:'passed',
  reviewReadonly:true,reviewIsolated:true,exitCode:0,
  evidenceId:EVIDENCE_ID,
  gates:Object.fromEntries([
    'ci','security','private_sse','pc','galaxy',
    'root_security','original_restore'
  ].map(k=>[k,{...VERDICT,evidenceId:'verified-'+k.replaceAll('_','-')+'-proof'}]))
});
const protection={
  repository:'al-hub/mcp-dev-hub',branch:'main',headSha:HEAD,
  enforceAdmins:true,requiredApprovals:0,reviewRuleAbsent:true,
  requireConversationResolution:true,
  requiredChecks:['bootstrap'],evidenceId:'verified-github-protected-policy'
};
const verified=()=>true;
const args=(api,ev=evidence())=>({
  api,actor:BOT,headSha:HEAD,prNumber:39,
  evidence:ev,verifyEvidence:verified,...receiptArgs,
  protectionEvidence:protection,verifyProtectionEvidence:verified
});
function fixture({draft=false,baseRepo='al-hub/mcp-dev-hub',
  head=HEAD,decision=null,author='developer',initialReviews=[]}={}){
  let posted=0;const reviews=[...initialReviews];const calls=[];
  async function api(method,path,body){
    calls.push({method,path,body});
    if(path==='/repos/al-hub/mcp-dev-hub/pulls/39')
      return {number:39,state:'open',draft,head:{sha:head},
        base:{ref:'main',sha:BASE,repo:{full_name:baseRepo}},
        user:{login:author}};
    if(path==='/repos/al-hub/mcp-dev-hub/pulls/39/reviews?per_page=100')
      return [...reviews];
    if(path==='/repos/al-hub/mcp-dev-hub/pulls/39/reviews'&&method==='POST'){
      posted++;
      const review={id:500,user:{login:BOT},state:'APPROVED',
        commit_id:body.commit_id,body:body.body,html_url:null};
      reviews.push(review);return review;
    }
    if(path==='/graphql')return {
      data:{repository:{pullRequest:{headRefOid:head,
        reviewDecision:decision}}}
    };
    throw Error('unexpected synthetic API call');
  }
  return {api,calls,get posted(){return posted}};
}
test('#35 exact PR39 verified Codex/root-security/recovery can route bot approval',async()=>{
  const f=fixture(),r=await publishIndependentApproval(args(f.api));
  assert.equal(r.state,'approved');assert.equal(r.headSha,HEAD);
  assert.equal(r.reviewId,500);assert.equal(f.posted,1);
  const post=f.calls.find(x=>x.method==='POST'&&x.path.endsWith('/reviews'));
  assert.equal(post.body.commit_id,HEAD);
  assert.equal(post.body.event,'APPROVE');
  const graph=f.calls.find(x=>x.path==='/graphql');
  assert.equal(graph.body.variables.number,39);
  const repeated=await publishIndependentApproval(args(f.api));
  assert.equal(repeated.reviewId,500);assert.equal(f.posted,1);
});
test('PR39 rejects missing privileged security gate and non-Codex evidence BEFORE API',async()=>{
  for(const mutate of [
    e=>{delete e.gates.root_security;},
    e=>{e.gates.original_restore.verdict='blocked';},
    e=>{e.scope='general';},
    e=>{e.prNumber=17;},
    e=>{e.reviewIsolated=false;},
    e=>{e.reviewerAgent='agy';}
  ]){
    const f=fixture(),e=evidence();mutate(e);
    await assert.rejects(publishIndependentApproval(args(f.api,e)));
    assert.equal(f.calls.length,0);assert.equal(f.posted,0);
  }
});
test('PR39 requires non-Draft, exact main repo and stable exact HEAD',async()=>{
  for(const variation of [
    {draft:true},{baseRepo:'fork/attacker'},
    {head:'b'.repeat(40)}
  ]){
    const f=fixture(variation);
    await assert.rejects(publishIndependentApproval(args(f.api)));
    assert.equal(f.posted,0);
  }
});
test('protected App approval cannot be redirected to any other PR',async()=>{
  const f=fixture();
  for(const prNumber of [1,18,38,40,100]){
    await assert.rejects(publishIndependentApproval({
      ...args(f.api),prNumber
    }));
  }
  assert.equal(f.calls.length,0);
});
test('PR39 with unverified out-of-band provenance is denied',async()=>{
  const f=fixture();
  await assert.rejects(publishIndependentApproval({
    ...args(f.api),verifyEvidence:()=>false
  }));
  assert.equal(f.calls.length,0);
});
test('PR39 separate app client preflight is exact and restricted',async()=>{
  const {privateKey}=generateKeyPairSync('rsa',{modulusLength:2048});
  const key=privateKey.export({type:'pkcs8',format:'pem'});
  const endpoints=[];
  const fetchImpl=async(url,options)=>{
    endpoints.push({url,options});
    return {ok:true,json:async()=>{
      if(url.endsWith('/app'))return {id:42,slug:'independent-reviewer'};
      if(url.includes('/access_tokens'))return {
        token:'synthetic-installation-token-123456789',
        permissions:{pull_requests:'write'}
      };
      if(url.endsWith('/pulls/39'))return {base:{repo:{id:99}}};
      if(url.endsWith('/pulls/39/reviews')&&options.method==='POST')
       return {id:702,body:JSON.parse(options.body).body};
      if(url.endsWith('/graphql')&&options.method==='POST')
       return {data:{repository:{pullRequest:{headRefOid:HEAD,reviewDecision:'APPROVED'}}}};
      throw Error('unknown synthetic URL');
    }};
  };
  const client=await createScopedAppClient({
    appId:42,installationId:123,repositoryId:99,key,
    fetchImpl,prNumber:39
  });
  assert.ok(endpoints.some(x=>x.url.endsWith('/pulls/39')));
  await assert.rejects(
    ()=>client.api('GET','/repos/al-hub/mcp-dev-hub/pulls/40'),
    /unapproved/
  );
  await assert.rejects(
    ()=>client.api('GET','/repos/al-hub/mcp-dev-hub/actions/runs'),
    /unapproved/
  );
  // A client pinned to PR39 must not expose the installation token as a
  // generic PR-edit or GraphQL mutation capability.
  const beforeDenied=endpoints.length;
  const reviewPath='/repos/al-hub/mcp-dev-hub/pulls/39/reviews';
  const validReview={commit_id:HEAD,event:'APPROVE',
    body:'AI-assisted independent Codex technical review (not a human review). Evidence: verified-safe-review'};
  for(const [method,path,body] of [
    ['PATCH','/repos/al-hub/mcp-dev-hub/pulls/39',{title:'changed'}],
    ['POST','/repos/al-hub/mcp-dev-hub/pulls/39',{state:'closed'}],
    ['POST','/graphql',{query:'mutation { __typename }',
      variables:{owner:'al-hub',name:'mcp-dev-hub',number:39}}],
    ['POST','/graphql',{query:'query { __typename }',variables:{}}],
    ['POST',reviewPath,{...validReview,event:'COMMENT'}],
    ['POST',reviewPath,{...validReview,body:'unverified human approval'}],
    ['POST',reviewPath,{...validReview,extra:'ignored'}],
    ['POST','/repos/al-hub/mcp-dev-hub/pulls/17/reviews',validReview],
    ['GET',reviewPath+'?per_page=100',{unexpected:true}]
  ])await assert.rejects(
    ()=>client.api(method,path,body),/unapproved/
  );
  assert.equal(endpoints.length,beforeDenied);
  // Preserve the two narrowly permitted operations used by the real
  // publisher after its independent provenance/PR validations.
  const approved=await client.api('POST',reviewPath,validReview);
  assert.equal(approved.id,702);
  const readonlyQuery='query($owner:String!,$name:String!,$number:Int!){repository(owner:$owner,name:$name){pullRequest(number:$number){headRefOid reviewDecision}}}';
  const graph=await client.api('POST','/graphql',{
    query:readonlyQuery,
    variables:{owner:'al-hub',name:'mcp-dev-hub',number:39}
  });
  assert.equal(graph.data.repository.pullRequest.headRefOid,HEAD);
  assert.equal(endpoints.length,beforeDenied+2);
});
test('PR17 existing workflow is still accepted without #35 privileged gates',()=>{
  const e=evidence();delete e.prNumber;delete e.scope;
  delete e.gates.root_security;delete e.gates.original_restore;
  assert.equal(validateReviewEvidence({
    headSha:HEAD,evidence:e,verifyEvidence:verified,prNumber:17
  }),true);
});

test('PR39 rejects fake global review requirements and unverified absent rule',async()=>{
  for(const patch of [
    {reviewRuleAbsent:false},{requiredApprovals:1},
    {reviewRuleAbsent:undefined},{requiredApprovals:undefined}
  ]){
    const f=fixture();
    await assert.rejects(publishIndependentApproval({
      ...args(f.api),protectionEvidence:{...protection,...patch}
    }));
    assert.equal(f.calls.length,0);assert.equal(f.posted,0);
  }
  const f=fixture();
  await assert.rejects(publishIndependentApproval({
    ...args(f.api),verifyProtectionEvidence:()=>false
  }));
  assert.equal(f.posted,0);
});
test('PR39 accepts authenticated real Bot review under nullable GitHub decision, not rejection',async()=>{
  const accepted=fixture({decision:'APPROVED'});
  assert.equal((await publishIndependentApproval(args(accepted.api))).state,'approved');
  const refused=fixture({decision:'REVIEW_REQUIRED'});
  await assert.rejects(publishIndependentApproval(args(refused.api)),
    /GitHub does not confirm/);
  assert.equal(refused.posted,1); // A submitted review is never blindly retried.
});

test('PR39 does not reuse a same-HEAD Bot approval tied to different evidence',async()=>{
  const f=fixture({initialReviews:[{
    id:490,user:{login:BOT},state:'APPROVED',commit_id:HEAD,
    body:'AI-assisted independent Codex technical review (not a human review). Evidence: verified-other-review'
  }]});
  await assert.rejects(publishIndependentApproval(args(f.api)),
    /reconciliation/);
  assert.equal(f.posted,0);
  assert.equal(f.calls.filter(x=>x.method==='POST').length,0);
});
test('PR39 rejects an existing same-HEAD Bot approval without evidence body',async()=>{
  const f=fixture({initialReviews:[{
    id:491,user:{login:BOT},state:'APPROVED',commit_id:HEAD
  }]});
  await assert.rejects(publishIndependentApproval(args(f.api)),
    /reconciliation/);
  assert.equal(f.posted,0);
});

test('PR39 denies absent, forged and wrong-package signed receipts BEFORE API',async()=>{
 for(const mutation of [
  {signedCodexReceipt:undefined},
  {signedCodexReceipt:{...signedCodexReceipt,signatureBase64:'AA=='}},
  {pinnedCodexPublicKeyPem:publicPem(generateKeyPairSync('ed25519'))},
  {pinnedIssuerReviewerPublicKeyPem:publicPem(codexKey)},
  {packDigest:'d'.repeat(64)},
  {baseSha:'d'.repeat(40)}
 ]){
  const f=fixture();
  await assert.rejects(publishIndependentApproval({...args(f.api),...mutation}));
  assert.equal(f.calls.length,0);
  assert.equal(f.posted,0);
 }
 const f=fixture(),altered=evidence();
 altered.evidenceId='verified-unrelated-code-review';
 await assert.rejects(publishIndependentApproval(args(f.api,altered)));
 assert.equal(f.calls.length,0);
});
test('PR39 denies changed actual main base before any Bot approval POST',async()=>{
 const f=fixture();
 const api=async(method,path,body)=>{
  const result=await f.api(method,path,body);
  if(method==='GET'&&path==='/repos/al-hub/mcp-dev-hub/pulls/39')
   result.base.sha='d'.repeat(40);
  return result;
 };
 await assert.rejects(publishIndependentApproval(args(api)));
 assert.equal(f.posted,0);
});

test('PR39 Codex receipt expires while GitHub requests are pending: no approval POST',async()=>{
 const f=fixture(),original=Date.now;
 let clock=now+1000,reads=0;
 Date.now=()=>clock;
 const api=async(method,path,body)=>{
  const r=await f.api(method,path,body);
  if(method==='GET'&&path.endsWith('/reviews?per_page=100')&&++reads===2)
   clock=now+300001;
  return r;
 };
 try{
  await assert.rejects(publishIndependentApproval(args(api)),
   /independent signed Codex receipt invalid/);
  assert.equal(f.posted,0);
 }finally{Date.now=original;}
});
test('PR39 cannot reuse a same-HEAD Bot review after receipt expires during final readback',async()=>{
 const expectedBody='AI-assisted independent Codex technical review (not a human review). Evidence: '+EVIDENCE_ID;
 const f=fixture({initialReviews:[{
  id:490,user:{login:BOT},state:'APPROVED',commit_id:HEAD,
  body:expectedBody
 }]}),original=Date.now;
 let clock=now+1000,prReads=0;
 Date.now=()=>clock;
 const api=async(method,path,body)=>{
  const r=await f.api(method,path,body);
  if(method==='GET'&&path==='/repos/al-hub/mcp-dev-hub/pulls/39'&&
     ++prReads===2)clock=now+300001;
  return r;
 };
 try{
  await assert.rejects(publishIndependentApproval(args(api)),
   /independent signed Codex receipt invalid/);
  assert.equal(f.posted,0);
 }finally{Date.now=original;}
});
