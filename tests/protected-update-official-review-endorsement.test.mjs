import test from 'node:test';
import assert from 'node:assert/strict';
import {validateOfficialReviewerApproval}
  from '../src/ops/protected-update-github-evidence.mjs';

const SHA='a'.repeat(40),PR=39,BOT_ID=12345678;
const NOW=Date.parse('2026-11-07T04:30:00.000Z');
const denied=fn=>assert.throws(fn,/protected_evidence_denied/);
function approved(patch={}){
  return {
    id:987654,commit_id:SHA,state:'APPROVED',
    user:{id:BOT_ID,type:'Bot',login:'reviewer-app[bot]'},
    pull_request_url:
      'https://api.github.com/repos/al-hub/mcp-dev-hub/pulls/39',
    submitted_at:new Date(NOW-30000).toISOString(),...patch
  };
}
const verify=(reviews=[approved()],extra={})=>
  validateOfficialReviewerApproval({reviews,head:SHA,prNumber:PR,
    reviewerBotId:BOT_ID,nowMs:NOW,...extra});
test('accept exact-HEAD latest official pinned reviewer App approval',()=>{
  const r=verify();
  assert.equal(r.state,'official_github_bot_review_confirmed');
  assert.equal(r.head,SHA);
  assert.equal(r.reviewId,987654);
  assert.equal(r.signerProvenanceVerified,false);
});
test('reject old commit, untrusted review writer and copied PR URL',()=>{
  for(const patch of [
    {commit_id:'b'.repeat(40)},
    {user:{id:BOT_ID+1,type:'Bot',login:'reviewer-app[bot]'}},
    {user:{id:BOT_ID,type:'User',login:'reviewer-app[bot]'}},
    {user:{id:BOT_ID,type:'Bot',login:'attacker'}},
    {pull_request_url:
      'https://api.github.com/repos/attacker/fork/pulls/39'},
    {state:'COMMENTED'}
  ])denied(()=>verify([approved(patch)]));
});
test('latest review dismisses previous APPROVED and denies replay',()=>{
  const old=approved({id:1,submitted_at:new Date(NOW-90000).toISOString()});
  const newer=approved({id:2,state:'CHANGES_REQUESTED',
    submitted_at:new Date(NOW-1000).toISOString()});
  denied(()=>verify([old,newer]));
  denied(()=>verify([old,{...newer,state:'DISMISSED'}]));
});
test('timestamp future, too old, malformed and truncated review pagination fail',()=>{
  for(const patch of [
    {submitted_at:new Date(NOW+1000).toISOString()},
    {submitted_at:new Date(NOW-8*86400000).toISOString()},
    {submitted_at:'invalid'}
  ])denied(()=>verify([approved(patch)]));
  denied(()=>verify([]));
  denied(()=>verify(Array.from({length:100},(_,i)=>approved({id:i+1}))));
});
test('untrusted caller cannot choose bot identity or HEAD',()=>{
  denied(()=>verify([approved()],{reviewerBotId:BOT_ID+1}));
  denied(()=>verify([approved()],{head:'c'.repeat(40)}));
  denied(()=>verify([approved()],{prNumber:17}));
});
