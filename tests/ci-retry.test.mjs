import test from 'node:test';
import assert from 'node:assert/strict';
import {decideCiRetry} from '../src/jobs/ci-retry.mjs';

test('transient failures are retried three times then blocked',()=>{
  for(let count=0;count<3;count++) {
    const outcome=decideCiRetry({retryCount:count,reason:'runner_lost'});
    assert.equal(outcome.retry,true);
    assert.equal(outcome.nextRetryCount,count+1);
    assert.equal(outcome.delayMs,[10000,30000,90000][count]);
  }
  assert.equal(decideCiRetry({retryCount:3,reason:'runner_lost'}).state,'blocked');
});
test('deterministic failures cannot replay the same SHA',()=>{
  for(const reason of ['test_failure','compile_error','auth','unknown'])
    assert.equal(decideCiRetry({reason}).retry,false);
});
test('unknown status or competing controller requires reconciliation',()=>{
  for(const flags of [{sameHead:false},{runCompleted:false},{anotherControllerActive:true}])
    assert.deepEqual(decideCiRetry({reason:'network',...flags}),{state:'reconcile',retry:false,delayMs:null});
});
test('retry counter validates input',()=>{
  assert.throws(()=>decideCiRetry({retryCount:-1,reason:'network'}));
});
