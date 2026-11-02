import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,createVerify} from 'node:crypto';
import {validateReviewEvidence,createAppJwt,publishIndependentApproval} from '../src/jobs/github-app-review-publisher.mjs';
const sha='a'.repeat(40),prNumber=17,actor='independent-reviewer[bot]';
const gates=Object.fromEntries(['ci','security','private_sse','pc','galaxy'].map(g=>[g,{verdict:'passed',headSha:sha,evidenceId:'verified-'+g}]));
const evidence=()=>({headSha:sha,authorAgent:'agy',reviewerAgent:'codex',verdict:'passed',reviewReadonly:true,
 reviewIsolated:true,exitCode:0,evidenceId:'verified-review-123456',gates});
const verifyEvidence=()=>true;
function mockApi({currentSha=sha,existing=[],decision='APPROVED',protectedBranch=true,ci=true}={}){
 let posted=0;const calls=[];
 async function api(method,path,body){
  calls.push({method,path});
  if(path.endsWith('/pulls/17'))return {number:17,state:'open',head:{sha:currentSha},base:{ref:'main'},user:{login:'author'}};
  if(path.endsWith('/branches/main/protection'))return {enforce_admins:{enabled:true},
   required_pull_request_reviews:{required_approving_review_count:protectedBranch?1:0,dismiss_stale_reviews:true},
   required_status_checks:{contexts:['bootstrap']}};
  if(path.includes('/actions/runs?'))return {workflow_runs:[{id:123,event:'pull_request',name:'CI',head_sha:sha,status:'completed',conclusion:ci?'success':'failure'}]};
  if(path.endsWith('/reviews?per_page=100'))return [...existing];
  if(path.endsWith('/reviews')&&method==='POST'){
   posted++;const review={id:99,user:{login:actor},state:'APPROVED',commit_id:body.commit_id};existing.push(review);return review;
  }
  if(path==='/graphql')return {data:{repository:{pullRequest:{reviewDecision:decision}}}};
  throw Error('unsupported test request');
 }
 return {api,calls,get posted(){return posted;}};
}
test('exact SHA validated independently before any API call',async()=>{
 const m=mockApi();const e=evidence();e.reviewIsolated=false;
 await assert.rejects(publishIndependentApproval({api:m.api,actor,headSha:sha,evidence:e,verifyEvidence}));
 assert.equal(m.calls.length,0);
 await assert.rejects(publishIndependentApproval({api:m.api,actor,headSha:sha,evidence:evidence(),verifyEvidence:()=>false}));
 assert.equal(m.calls.length,0);
});
test('moved PR SHA, missing protection and failed CI block approval',async()=>{
 for(const scenario of [{currentSha:'b'.repeat(40)},{protectedBranch:false},{ci:false}]){
  const m=mockApi(scenario);
  await assert.rejects(publishIndependentApproval({api:m.api,actor,headSha:sha,evidence:evidence(),verifyEvidence}));
  assert.equal(m.posted,0);
 }
});
test('approved exact-HEAD Bot review is idempotent and observed on GitHub',async()=>{
 const m=mockApi();const args={api:m.api,actor,headSha:sha,evidence:evidence(),verifyEvidence};
 const result=await publishIndependentApproval(args);
 assert.equal(result.state,'approved');assert.equal(result.reviewId,99);assert.equal(m.posted,1);
 const repeat=await publishIndependentApproval(args);
 assert.equal(repeat.reviewId,99);assert.equal(m.posted,1);
});
test('GitHub policy nonrecognition is BLOCKED even after review POST; no implicit replay',async()=>{
 const m=mockApi({decision:'REVIEW_REQUIRED'});
 await assert.rejects(publishIndependentApproval({api:m.api,actor,headSha:sha,evidence:evidence(),verifyEvidence}),/GitHub does not confirm/);
 assert.equal(m.posted,1);
});
test('other author, stale or changes-requested reviewer is rejected',async()=>{
 const m=mockApi({existing:[{id:71,user:{login:actor},state:'CHANGES_REQUESTED',commit_id:sha}]});
 await assert.rejects(publishIndependentApproval({api:m.api,actor,headSha:sha,evidence:evidence(),verifyEvidence}),/reconciliation/);
 assert.equal(m.posted,0);
});
test('GitHub App JWT is signed with RS256 and short-lived',()=>{
 const {privateKey,publicKey}=generateKeyPairSync('rsa',{modulusLength:2048});
 const value=createAppJwt({appId:42,privateKey:privateKey.export({type:'pkcs8',format:'pem'}),now:1000});
 const parts=value.split('.');assert.equal(parts.length,3);
 const verifier=createVerify('RSA-SHA256');verifier.update(parts[0]+'.'+parts[1]);verifier.end();
 assert.equal(verifier.verify(publicKey,parts[2],'base64url'),true);
 assert.equal(JSON.parse(Buffer.from(parts[1],'base64url')).exp,1540);
});
