import test from 'node:test';
import assert from 'node:assert/strict';
import {DatabaseSync} from 'node:sqlite';
import {trackPr,recordPrGate,prNextAction} from '../src/jobs/pr-automation.mjs';
const prKey='al-hub/mcp-dev-hub#17',a='a'.repeat(40),b='b'.repeat(40);
const gates=['ci','independent_review','security','private_sse','pc','galaxy'];
test('gates must all pass for same pinned SHA before merge',()=>{
 const db=new DatabaseSync(':memory:');
 trackPr(db,{prKey,headSha:a});
 assert.deepEqual(prNextAction(db,{prKey,observedSha:a}).action,'verify');
 for(const [i,gate] of gates.entries()){
  recordPrGate(db,{prKey,headSha:a,gate,verdict:'passed',evidenceId:'verified-'+gate});
  const result=prNextAction(db,{prKey,observedSha:a});
  assert.equal(result.action,i===gates.length-1?'request_guarded_merge':'verify');
 }
 assert.equal(prNextAction(db,{prKey,observedSha:a}).state,'merge_eligible');
 assert.equal(prNextAction(db,{prKey,observedSha:b}).action,'reconcile');
 db.close();
});
test('new SHA revokes all old gate evidence; blocked gates never merge',()=>{
 const db=new DatabaseSync(':memory:');
 trackPr(db,{prKey,headSha:a});
 recordPrGate(db,{prKey,headSha:a,gate:'ci',verdict:'passed',evidenceId:'ci-previous'});
 assert.equal(trackPr(db,{prKey,headSha:b}).changed,true);
 assert.equal(prNextAction(db,{prKey,observedSha:b}).gate,'ci');
 assert.throws(()=>recordPrGate(db,{prKey,headSha:a,gate:'pc',verdict:'passed',evidenceId:'old-pc'}),/stale/);
 recordPrGate(db,{prKey,headSha:b,gate:'ci',verdict:'blocked',evidenceId:'run-uncertain'});
 assert.equal(prNextAction(db,{prKey,observedSha:b}).state,'blocked');
 db.close();
});
test('reject unsupported scopes and missing evidence',()=>{
 const db=new DatabaseSync(':memory:');
 trackPr(db,{prKey,headSha:a});
 assert.throws(()=>recordPrGate(db,{prKey,headSha:a,gate:'invalid',verdict:'passed',evidenceId:'test-123'}));
 assert.throws(()=>recordPrGate(db,{prKey,headSha:a,gate:'ci',verdict:'passed',evidenceId:''}));
 db.close();
});
