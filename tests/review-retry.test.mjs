import test from 'node:test';
import assert from 'node:assert/strict';
import {MAX_RETRIES,decideReviewRetry} from '../src/jobs/review-retry.mjs';

test('transient failures schedule at most three automatic retries',()=>{
  assert.equal(MAX_RETRIES,3);
  assert.deepEqual([1,2,3].map(attempt=>decideReviewRetry({attempt,reason:'timeout'}).delayMs),[10000,30000,90000]);
  assert.deepEqual([1,2,3].map(attempt=>decideReviewRetry({attempt,reason:'timeout'}).nextAttempt),[2,3,4]);
  assert.deepEqual(decideReviewRetry({attempt:4,reason:'timeout'}),{state:'blocked',retry:false,delayMs:null});
});
test('uncertain or live work must not be replayed',()=>{
  assert.equal(decideReviewRetry({attempt:1,reason:'timeout',processAlive:true}).state,'recovering');
  assert.equal(decideReviewRetry({attempt:1,reason:'timeout',outcomeKnown:false}).state,'recovering');
});
test('permanent failures are blocked immediately',()=>{
  for(const reason of ['auth','permission','policy','invalid_input','code_failure']) {
    assert.equal(decideReviewRetry({attempt:1,reason}).retry,false);
  }
});
test('invalid attempts are rejected',()=>assert.throws(()=>decideReviewRetry({attempt:0,reason:'timeout'}),/invalid attempt/));
