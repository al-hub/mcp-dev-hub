import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync} from 'node:crypto';
import {createScopedAppClient,publishIndependentApproval} from '../src/jobs/github-app-review-publisher.mjs';
const sha='a'.repeat(40),different='b'.repeat(40),actor='independent-reviewer[bot]';
const gates=Object.fromEntries(['ci','security','private_sse','pc','galaxy'].map(k=>[k,{verdict:'passed',headSha:sha,evidenceId:'verified-'+k}]));
const evidence={headSha:sha,authorAgent:'agy',reviewerAgent:'codex',verdict:'passed',reviewReadonly:true,reviewIsolated:true,exitCode:0,evidenceId:'verified-review-123456',gates};
const protectionEvidence={repository:'al-hub/mcp-dev-hub',branch:'main',headSha:sha,enforceAdmins:true,requiredApprovals:1,dismissStaleReviews:true,requireLastPushApproval:true,requireConversationResolution:true,requiredChecks:['bootstrap'],evidenceId:'verified-protection-123456'};
const params={actor,headSha:sha,evidence,verifyEvidence:()=>true,protectionEvidence,verifyProtectionEvidence:()=>true};
function fixture({moveBeforePost=false,graphSha=sha,denyPolicyApi=false}={}){
 let posted=0,prReads=0,policyCalls=0;const reviews=[];
 async function api(method,path,body){
  if(path.endsWith('/pulls/17')){prReads++;return {number:17,state:'open',head:{sha:moveBeforePost&&prReads>1?different:sha},base:{ref:'main'},user:{login:'author'}};}
  if(path.includes('/branches/main/protection')){policyCalls++;if(denyPolicyApi)throw Error('reviewer app cannot read branch protection');return {enforce_admins:{enabled:true},required_pull_request_reviews:{required_approving_review_count:1,dismiss_stale_reviews:true},required_status_checks:{contexts:['bootstrap']}};}
  if(path.includes('/actions/runs?'))return {workflow_runs:[{id:4,event:'pull_request',name:'CI',head_sha:sha,status:'completed',conclusion:'success'}]};
  if(path.endsWith('/reviews?per_page=100'))return reviews;
  if(path.endsWith('/reviews')&&method==='POST'){posted++;const row={id:99,user:{login:actor},state:'APPROVED',commit_id:body.commit_id,html_url:'https://github.com/al-hub/mcp-dev-hub/pull/17#pullrequestreview-99'};reviews.push(row);return row;}
  if(path==='/graphql')return {data:{repository:{pullRequest:{headRefOid:graphSha,reviewDecision:'APPROVED'}}}};
  throw Error('unexpected request');
 }
 return {api,get posted(){return posted},get prReads(){return prReads},get policyCalls(){return policyCalls}};
}
test('reviewer App client cannot request branch protection with Pull requests:write token',async()=>{
 const {privateKey}=generateKeyPairSync('rsa',{modulusLength:2048});
 const key=privateKey.export({type:'pkcs8',format:'pem'});
 const fetchImpl=async (url,options)=>({ok:true,json:async()=>{
  if(url.endsWith('/app'))return {id:42,slug:'independent-reviewer'};
  if(url.includes('/access_tokens'))return {token:'synthetic-installation-token-123456789',permissions:{pull_requests:'write'}};
  if(url.endsWith('/pulls/17'))return {base:{repo:{id:99}}};
  if(url.includes('/branches/main/protection'))return {enforce_admins:{enabled:true}};
  throw Error('unexpected API call '+url);
 }});
 const client=await createScopedAppClient({appId:42,installationId:123,repositoryId:99,key,fetchImpl});
 await assert.rejects(()=>client.api('GET','/repos/al-hub/mcp-dev-hub/branches/main/protection'),/unapproved/);
});
test('trusted out-of-band policy evidence allows approval without privileged App policy endpoint',async()=>{
 const f=fixture({denyPolicyApi:true});
 const r=await publishIndependentApproval({api:f.api,...params});
 assert.equal(r.state,'approved');assert.equal(f.posted,1);assert.equal(f.policyCalls,0);
});
test('review approval POST is blocked when PR head changes after initial check',async()=>{
 const f=fixture({moveBeforePost:true});
 await assert.rejects(()=>publishIndependentApproval({api:f.api,...params}));
 assert.equal(f.posted,0);assert.ok(f.prReads>=2);
});
test('GraphQL review decision on a different HEAD cannot confirm approval',async()=>{
 const f=fixture({graphSha:different});
 await assert.rejects(()=>publishIndependentApproval({api:f.api,...params}));
 assert.equal(f.posted,1);
});
test('absent or unverified trusted policy evidence must fail before approval API calls',async()=>{
 const f=fixture();
 await assert.rejects(()=>publishIndependentApproval({api:f.api,...params,protectionEvidence:undefined}));
 assert.equal(f.posted,0);
 const g=fixture();
 await assert.rejects(()=>publishIndependentApproval({api:g.api,...params,verifyProtectionEvidence:()=>false}));
 assert.equal(g.posted,0);
});
