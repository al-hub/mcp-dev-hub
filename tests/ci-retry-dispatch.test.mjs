import test from 'node:test';
import assert from 'node:assert/strict';
import {DatabaseSync} from 'node:sqlite';
import {scheduleCiRetry} from '../src/jobs/ci-retry-store.mjs';
import {dispatchScheduledCiRetry} from '../src/jobs/ci-retry-dispatch.mjs';
const sha='a'.repeat(40);
test('only one authorized GitHub rerun dispatch is attempted',async()=>{
 const db=new DatabaseSync(':memory:');
 scheduleCiRetry(db,{runId:12,headSha:sha,reason:'network',now:0});
 let calls=0;
 const fetchImpl=async(url,opts)=>{calls++;assert.match(url,/\/actions\/runs\/12\/rerun-failed-jobs$/);assert.equal(opts.method,'POST');return {status:201};};
 const args={runId:12,repo:'al-hub/mcp-dev-hub',token:'test-secret',now:10000,fetchImpl};
 assert.equal((await dispatchScheduledCiRetry(db,args)).dispatched,true);
 assert.equal((await dispatchScheduledCiRetry(db,args)).dispatched,false);
 assert.equal(calls,1);
 assert.equal(db.prepare('SELECT state FROM ci_retry_runs WHERE run_id=12').get().state,'reconciling');
 db.close();
});
test('unknown outcome holds automatic retry',async()=>{
 const db=new DatabaseSync(':memory:');
 scheduleCiRetry(db,{runId:13,headSha:sha,reason:'network',now:0});
 const args={runId:13,repo:'al-hub/mcp-dev-hub',token:'test-secret',now:10000,fetchImpl:async()=>{throw Error('network disconnected');}};
 assert.equal((await dispatchScheduledCiRetry(db,args)).state,'unknown');
 assert.equal((await dispatchScheduledCiRetry(db,args)).dispatched,false);
 assert.equal(db.prepare('SELECT retry_count FROM ci_retry_runs WHERE run_id=13').get().retry_count,1);
 db.close();
});
