import test from 'node:test';
import assert from 'node:assert/strict';
import {PROTECTED_PAIR,startProtectedUpdateJournal,advanceProtectedUpdateJournal,
  parseProtectedUpdateJournal}
  from '../src/ops/protected-update-journal.mjs';
const oldHashes=Object.fromEntries(PROTECTED_PAIR.map(n=>[n,'a'.repeat(64)]));
const newHashes=Object.fromEntries(PROTECTED_PAIR.map(n=>[n,'b'.repeat(64)]));
const operationId='c'.repeat(32);
const make=()=>startProtectedUpdateJournal({
  operationId,head:'d'.repeat(40),base:'e'.repeat(40),
  previousCommit:'a'.repeat(40),oldHashes,newHashes,nowMs:1000
});
const step=(j,to,extra={})=>advanceProtectedUpdateJournal(j,{
  operationId,expectedSequence:j.sequence,to,nowMs:1001+j.sequence,
  ...extra
});
test('a staged attempt is journaled BEFORE an external switch and reviewed after',()=>{
  let j=make();
  assert.equal(j.phase,'prepared');
  j=step(j,'switch_pending');
  assert.equal(j.sequence,1);
  j=step(j,'switched',{observedHashes:newHashes});
  j=step(j,'verified',{observedHashes:newHashes,serviceHealthVerified:true});
  assert.equal(j.phase,'verified');
  assert.equal(j.sequence,3);
  assert.ok(Object.isFrozen(j));
  assert.ok(Object.isFrozen(j.newHashes));
  assert.throws(()=>step(j,'switch_pending'),/invalid_protected_update_journal/);
});
test('uncertain switch blocks blind replay or success',()=>{
  const prepared=make();
  const pending=step(prepared,'switch_pending');
  const unknown=step(pending,'unknown');
  assert.throws(()=>step(unknown,'switched',{observedHashes:newHashes}));
  assert.throws(()=>step(pending,'switch_pending'));
  assert.throws(()=>step(pending,'verified',{observedHashes:newHashes,serviceHealthVerified:true}));
});
test('an observed rollback is only terminal with the original exact pair',()=>{
  let j=step(make(),'switch_pending');
  assert.throws(()=>step(j,'rolled_back',{observedHashes:newHashes}));
  j=step(j,'switched',{observedHashes:newHashes});
  j=step(j,'rollback_pending');
  j=step(j,'rolled_back',{observedHashes:oldHashes});
  assert.equal(j.phase,'rolled_back');
  assert.throws(()=>step(j,'verified',{observedHashes:newHashes,serviceHealthVerified:true}));
});
test('partial/mixed hashes, false health and absent proof cannot succeed',()=>{
  let j=step(make(),'switch_pending');
  const mixed={...newHashes,[PROTECTED_PAIR[0]]:oldHashes[PROTECTED_PAIR[0]]};
  assert.throws(()=>step(j,'switched',{observedHashes:mixed}));
  assert.throws(()=>step(j,'switched'));
  j=step(j,'switched',{observedHashes:newHashes});
  assert.throws(()=>step(j,'verified',{observedHashes:newHashes}));
  assert.throws(()=>step(j,'verified',{observedHashes:oldHashes,serviceHealthVerified:true}));
  assert.throws(()=>step(j,'verified',{observedHashes:newHashes,serviceHealthVerified:false}));
});
test('must exactly match persistent operation ID, sequence and clock',()=>{
  const j=make();
  assert.throws(()=>advanceProtectedUpdateJournal(j,{
    operationId:'f'.repeat(32),expectedSequence:0,to:'switch_pending',nowMs:1001
  }));
  assert.throws(()=>advanceProtectedUpdateJournal(j,{
    operationId,expectedSequence:1,to:'switch_pending',nowMs:1001
  }));
  assert.throws(()=>advanceProtectedUpdateJournal(j,{
    operationId,expectedSequence:0,to:'switch_pending',nowMs:999
  }));
});
test('untrusted scope, malformed fields, no-op and prototype keys denied',()=>{
  assert.throws(()=>startProtectedUpdateJournal({
    operationId,head:'d'.repeat(40),base:'e'.repeat(40),
    previousCommit:'a'.repeat(40),oldHashes,newHashes:oldHashes,nowMs:1000
  }));
  assert.throws(()=>startProtectedUpdateJournal({
    operationId,head:'d'.repeat(40),base:'e'.repeat(40),
    previousCommit:'a'.repeat(40),oldHashes:{...oldHashes,sudoers:'0'.repeat(64)},
    newHashes,nowMs:1000
  }));
  const j=make();
  assert.throws(()=>step({...j,__proto_exploit:1},'switch_pending'));
  assert.throws(()=>step({...j,phase:'garbage'},'switch_pending'));
});

test('rejects coerced arrays in every journal identifier before freeze and readback',()=>{
  const j=make();
  const cases=[
    {operationId:[operationId]},
    {head:['d'.repeat(40)]},
    {base:['e'.repeat(40)]},
    {previousCommit:['a'.repeat(40)]},
    {phase:['prepared']},
    {head:['d'.repeat(40)],base:['d'.repeat(40)]}
  ];
  for(const changes of cases){
    const malformed={...j,...changes};
    assert.throws(()=>parseProtectedUpdateJournal(JSON.stringify(malformed)),
      /invalid_protected_update_journal/);
    assert.throws(()=>advanceProtectedUpdateJournal(malformed,{
      operationId,expectedSequence:0,to:'switch_pending',nowMs:1001
    }),/invalid_protected_update_journal/);
    if(Object.hasOwn(changes,'operationId')||
       Object.hasOwn(changes,'head')||Object.hasOwn(changes,'base')||
       Object.hasOwn(changes,'previousCommit'))
      assert.throws(()=>startProtectedUpdateJournal({
        operationId:malformed.operationId,head:malformed.head,
        base:malformed.base,previousCommit:malformed.previousCommit,
        oldHashes,newHashes,nowMs:1000
      }),/invalid_protected_update_journal/);
  }
});

test('durable v2 journal preserves trusted previous release identity',()=>{
  const j=make();
  assert.equal(j.version,2);
  assert.equal(j.previousCommit,'a'.repeat(40));
  assert.equal(parseProtectedUpdateJournal(JSON.stringify(j)).previousCommit,
    j.previousCommit);
  assert.equal(step(j,'switch_pending').previousCommit,j.previousCommit);
  const legacy={...j,version:1};
  delete legacy.previousCommit;
  assert.throws(()=>parseProtectedUpdateJournal(JSON.stringify(legacy)),
    /invalid_protected_update_journal/);
});
test('same new and previous release or malformed previous commit is denied',()=>{
  const j=make();
  assert.throws(()=>startProtectedUpdateJournal({
    operationId,head:j.head,base:j.base,previousCommit:j.head,
    oldHashes,newHashes,nowMs:1000
  }),/invalid_protected_update_journal/);
  assert.throws(()=>startProtectedUpdateJournal({
    operationId,head:j.head,base:j.base,previousCommit:'../invalid',
    oldHashes,newHashes,nowMs:1000
  }),/invalid_protected_update_journal/);
});
