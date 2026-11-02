import test from 'node:test';
import assert from 'node:assert/strict';
import {DatabaseSync} from 'node:sqlite';
import {scheduleCiRetry} from '../src/jobs/ci-retry-store.mjs';
import {dispatchDueCiRetries} from '../scripts/worker.mjs';
const sha='a'.repeat(40);
test('Worker dispatches due retries, once, with exact configured scope',async()=>{
 const db=new DatabaseSync(':memory:');
 scheduleCiRetry(db,{runId:88,headSha:sha,reason:'network',now:0});
 const oldRepo=process.env.MCP_DEV_HUB_GITHUB_REPOSITORY,oldToken=process.env.MCP_DEV_HUB_GITHUB_TOKEN;
 try {
   delete process.env.MCP_DEV_HUB_GITHUB_REPOSITORY; delete process.env.MCP_DEV_HUB_GITHUB_TOKEN;
   assert.equal(await dispatchDueCiRetries(db,{at:10000}),0);
   process.env.MCP_DEV_HUB_GITHUB_REPOSITORY='al-hub/mcp-dev-hub';
   process.env.MCP_DEV_HUB_GITHUB_TOKEN='test-only';
   let calls=0;
   const dispatch=async (_db,args)=>{calls++;assert.equal(args.runId,88);assert.equal(args.repo,'al-hub/mcp-dev-hub');assert.equal(args.token,'test-only');_db.prepare("UPDATE ci_retry_runs SET state='reconciling' WHERE run_id=88").run();};
   assert.equal(await dispatchDueCiRetries(db,{at:9999,dispatch}),0);
   assert.equal(await dispatchDueCiRetries(db,{at:10000,dispatch}),1);
   assert.equal(await dispatchDueCiRetries(db,{at:10000,dispatch}),0);
   assert.equal(calls,1);
 } finally {
   if(oldRepo===undefined)delete process.env.MCP_DEV_HUB_GITHUB_REPOSITORY;else process.env.MCP_DEV_HUB_GITHUB_REPOSITORY=oldRepo;
   if(oldToken===undefined)delete process.env.MCP_DEV_HUB_GITHUB_TOKEN;else process.env.MCP_DEV_HUB_GITHUB_TOKEN=oldToken;
   db.close();
 }
});
