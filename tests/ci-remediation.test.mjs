import test from 'node:test';
import assert from 'node:assert/strict';
import {decideCiRemediation,acceptFixedHead} from '../src/jobs/ci-remediation.mjs';
const oldSha='a'.repeat(40),newSha='b'.repeat(40);
test('deterministic CI failure enters bounded AI fix path',()=>{
 for(let attempts=0;attempts<3;attempts++){
  const d=decideCiRemediation({attempts,reason:'test_failure',headSha:oldSha,observedSha:oldSha,reviewerIndependent:true});
  assert.equal(d.allowed,true);assert.equal(d.nextAttempt,attempts+1);
 }
 assert.equal(decideCiRemediation({attempts:3,reason:'test_failure',headSha:oldSha,observedSha:oldSha,reviewerIndependent:true}).state,'blocked');
 assert.equal(decideCiRemediation({reason:'network',headSha:oldSha,observedSha:oldSha,reviewerIndependent:true}).allowed,false);
 assert.equal(decideCiRemediation({reason:'compile_failure',headSha:oldSha,observedSha:newSha,reviewerIndependent:true}).state,'reconcile');
 assert.equal(decideCiRemediation({reason:'lint_failure',headSha:oldSha,observedSha:oldSha}).state,'blocked');
});
test('new SHA and independent review and acceptance are mandatory before merge',()=>{
 assert.equal(acceptFixedHead({oldSha,newSha:oldSha,ciPassed:true,independentReviewPassed:true,acceptancePassed:true}).merge,false);
 assert.equal(acceptFixedHead({oldSha,newSha,ciPassed:true,independentReviewPassed:false,acceptancePassed:true}).merge,false);
 assert.equal(acceptFixedHead({oldSha,newSha,ciPassed:true,independentReviewPassed:true,acceptancePassed:true}).state,'merge_eligible');
});
