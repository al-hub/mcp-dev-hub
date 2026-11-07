import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync} from 'node:crypto';
import {createScopedAppClient,publishIndependentApproval,
  validateReviewEvidence} from '../src/jobs/github-app-review-publisher.mjs';

const HEAD='a'.repeat(40),BOT='independent-reviewer[bot]';
const VERDICT={headSha:HEAD,verdict:'passed'};
const evidence=()=>({
  headSha:HEAD,prNumber:39,scope:'protected-bootstrap',
  authorAgent:'agy',reviewerAgent:'codex',verdict:'passed',
  reviewReadonly:true,reviewIsolated:true,exitCode:0,
  evidenceId:'verified-independent-review-35',
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
  evidence:ev,verifyEvidence:verified,
  protectionEvidence:protection,verifyProtectionEvidence:verified
});
function fixture({draft=false,baseRepo='al-hub/mcp-dev-hub',
  head=HEAD,decision=null,author='developer'}={}){
  let posted=0;const reviews=[];const calls=[];
  async function api(method,path,body){
    calls.push({method,path,body});
    if(path==='/repos/al-hub/mcp-dev-hub/pulls/39')
      return {number:39,state:'open',draft,head:{sha:head},
        base:{ref:'main',repo:{full_name:baseRepo}},
        user:{login:author}};
    if(path==='/repos/al-hub/mcp-dev-hub/pulls/39/reviews?per_page=100')
      return [...reviews];
    if(path==='/repos/al-hub/mcp-dev-hub/pulls/39/reviews'&&method==='POST'){
      posted++;
      const review={id:500,user:{login:BOT},state:'APPROVED',
        commit_id:body.commit_id,html_url:null};
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
