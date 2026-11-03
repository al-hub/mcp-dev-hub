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
