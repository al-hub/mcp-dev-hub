import test from 'node:test';
import assert from 'node:assert/strict';
import {checkReviewerConnection} from '../scripts/reviewer-app-connect.mjs';

const sha='a'.repeat(40);
const env={
 MCP_DEV_HUB_REVIEWER_APP_ID:'42',
 MCP_DEV_HUB_REVIEWER_APP_INSTALLATION_ID:'123',
 MCP_DEV_HUB_REVIEWER_APP_PRIVATE_KEY_FILE:'/var/lib/example/test-reviewer.pem',
 MCP_DEV_HUB_REVIEWER_EXPECTED_HEAD_SHA:sha
};

test('missing runtime app configuration blocks before key access',async()=>{
 let touched=false;
 const r=await checkReviewerConnection({env:{},readKey:()=>{touched=true;throw Error('should not read')},createClient:()=>{throw Error('should not call')}});
 assert.equal(r.status,'blocked');assert.equal(r.reason,'configuration_missing');assert.equal(touched,false);
});

test('authenticated scoped App and exact PR HEAD are needed for ready',async()=>{
 let keyCalls=0,clientCalls=0,apiCalls=0;
 const r=await checkReviewerConnection({env,
  readKey:()=>{keyCalls++;return 'synthetic-test-key'},
  createClient:async args=>{
   clientCalls++;assert.equal(args.appId,42);
   assert.equal(args.installationId,123);
   assert.equal(args.repositoryId,1440361577);
   return {actor:'mcp-dev-hub-ai-reviewer[bot]',api:async (method,path)=>{
    apiCalls++;assert.equal(method,'GET');
    assert.equal(path,'/repos/al-hub/mcp-dev-hub/pulls/17');
    return {number:17,state:'open',head:{sha},base:{ref:'main'},user:{login:'al-hub'}};
   }};
  }});
 assert.deepEqual(r,{status:'ready',actor:'mcp-dev-hub-ai-reviewer[bot]',headSha:sha,prNumber:17});
 assert.equal(keyCalls,1);assert.equal(clientCalls,1);assert.equal(apiCalls,1);
});

test('different App identity cannot be accepted',async()=>{
 const r=await checkReviewerConnection({env,readKey:()=> 'synthetic-test-key',
  createClient:async()=>({actor:'another-app[bot]',api:async()=>{throw Error('must never query PR')}})});
 assert.equal(r.status,'blocked');
 assert.equal(r.reason,'app_identity_or_pr_unverified');
});

test('stale PR HEAD or PR not open blocks without submission',async()=>{
 for(const row of [
  {number:17,state:'open',head:{sha:'b'.repeat(40)},base:{ref:'main'},user:{login:'al-hub'}},
  {number:17,state:'closed',head:{sha},base:{ref:'main'},user:{login:'al-hub'}},
  {number:17,state:'open',head:{sha},base:{ref:'main'},user:{login:'mcp-dev-hub-ai-reviewer[bot]'}}
 ]){
  const r=await checkReviewerConnection({env,readKey:()=> 'synthetic-test-key',
   createClient:async()=>({actor:'mcp-dev-hub-ai-reviewer[bot]',api:async()=>row})});
  assert.equal(r.status,'blocked');assert.equal(r.reason,'app_identity_or_pr_unverified');
 }
});

test('invalid expected SHA blocks before key access',async()=>{
 let reads=0;
 const r=await checkReviewerConnection({env:{...env,MCP_DEV_HUB_REVIEWER_EXPECTED_HEAD_SHA:'invalid'},
  readKey:()=>{reads++;return 'bad'},createClient:async()=>{throw Error('not allowed')}});
 assert.equal(r.status,'blocked');assert.equal(reads,0);
});

test('existing reviewer App may target #39 only when non-Draft same-HEAD main PR',async()=>{
 const targetEnv={...env,MCP_DEV_HUB_REVIEWER_TARGET_PR:'39'};
 const checked=[];
 const r=await checkReviewerConnection({
  env:targetEnv,readKey:()=> 'synthetic-test-key',
  createClient:async args=>{
   assert.equal(args.prNumber,39);
   return {actor:'mcp-dev-hub-ai-reviewer[bot]',
    api:async(method,path)=>{
     checked.push(path);
     return {number:39,state:'open',draft:false,
      head:{sha},base:{ref:'main',
       repo:{full_name:'al-hub/mcp-dev-hub'}},user:{login:'al-hub'}};
    }};
  }
 });
 assert.deepEqual(checked,['/repos/al-hub/mcp-dev-hub/pulls/39']);
 assert.equal(r.status,'ready');
 assert.equal(r.prNumber,39);
});
test('PR39 Draft, cross-repo and attacker-controlled PR flags fail closed',async()=>{
 for(const patch of [
  {draft:true},
  {base:{ref:'main',repo:{full_name:'attacker/repository'}}},
  {state:'closed'}
 ]){
  const r=await checkReviewerConnection({
   env:{...env,MCP_DEV_HUB_REVIEWER_TARGET_PR:'39'},
   readKey:()=> 'synthetic-test-key',
   createClient:async()=>({
    actor:'mcp-dev-hub-ai-reviewer[bot]',
    api:async()=>({number:39,state:'open',draft:false,
      head:{sha},base:{ref:'main',
       repo:{full_name:'al-hub/mcp-dev-hub'}},
      user:{login:'al-hub'},...patch})
   })
  });
  assert.equal(r.status,'blocked');
 }
});
test('arbitrary reviewer App PR target fails before key access',async()=>{
 for(const target of ['1','38','40','abc','','39/other']){
  let read=false;
  const r=await checkReviewerConnection({
   env:{...env,MCP_DEV_HUB_REVIEWER_TARGET_PR:target},
   readKey:()=>{read=true;throw Error('must not read');},
   createClient:async()=>{throw Error('must not call');}
  });
  assert.equal(r.status,'blocked');
  assert.equal(read,false);
 }
});
