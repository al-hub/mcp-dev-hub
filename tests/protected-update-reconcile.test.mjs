import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {
  chmodSync,mkdirSync,mkdtempSync,readFileSync,readlinkSync,
  readdirSync,rmSync,writeFileSync
} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {
  RELEASE_FILES,stageProtectedRelease,switchProtectedRelease
} from '../src/ops/protected-update-release-pointer.mjs';
import {
  beginStoredProtectedUpdateJournal,advanceStoredProtectedUpdateJournal
} from '../src/ops/protected-update-journal-store.mjs';
import {reconcileProtectedUpdateCandidate}
  from '../src/ops/protected-update-reconcile.mjs';

const A='a'.repeat(40),B='b'.repeat(40),C='d'.repeat(40);
const ID='c'.repeat(32),ID2='e'.repeat(32);
const digest=buf=>createHash('sha256').update(buf).digest('hex');
function makeFiles(tag){
  const contents=Object.fromEntries(RELEASE_FILES.map((name,i)=>
    [name,Buffer.from('synthetic-'+tag+'-'+i+'\n')]));
  const files=RELEASE_FILES.map(name=>({
    name,bytes:contents[name].length,sha256:digest(contents[name])
  }));
  return {contents,files};
}
const hashes=files=>Object.fromEntries(files.map(f=>[f.name,f.sha256]));
function fixture(t){
  const top=mkdtempSync(join(tmpdir(),'protected-reconcile-'));
  const root=join(top,'release'),stateDir=join(top,'journal');
  mkdirSync(root,{mode:0o755});
  mkdirSync(join(root,'versions'),{mode:0o755});
  mkdirSync(stateDir,{mode:0o700});
  chmodSync(root,0o755);
  chmodSync(join(root,'versions'),0o755);
  const old=makeFiles('A'),next=makeFiles('B'),third=makeFiles('C');
  stageProtectedRelease(root,{commit:A,...old});
  stageProtectedRelease(root,{commit:B,...next});
  stageProtectedRelease(root,{commit:C,...third});
  switchProtectedRelease(root,{
    expectedCommit:null,nextCommit:A,nextFiles:old.files
  });
  t.after(()=>{
    for(const name of readdirSync(join(root,'versions'))){
      chmodSync(join(root,'versions',name),0o700);
    }
    rmSync(top,{recursive:true,force:true});
  });
  return {root,stateDir,old,next,third};
}
function begin(f,previousCommit=A){
  return beginStoredProtectedUpdateJournal(f.stateDir,{
    operationId:ID,head:B,base:A,previousCommit,
    oldHashes:hashes(f.old.files),
    newHashes:hashes(f.next.files),nowMs:100
  });
}
function advance(f,j,to,nowMs,extra={}){
  return advanceStoredProtectedUpdateJournal(f.stateDir,ID,{
    expectedSequence:j.sequence,to,nowMs,...extra
  });
}
function inspect(f){
  return reconcileProtectedUpdateCandidate({
    root:f.root,stateDir:f.stateDir,operationId:ID
  });
}
const denied=fn=>assert.throws(fn,/protected_update_reconciliation_denied|protected_release_guard_failed|protected_journal_store_guard_failed/);

test('read-only absent operation never authorizes replay',t=>{
  const f=fixture(t);
  assert.deepEqual(inspect(f),{
    operationId:ID,state:'absent',observed:'unverified',
    safeToReplay:false,requiresReconciliation:true
  });
  assert.deepEqual(readdirSync(f.stateDir),[]);
});

test('prepared and switch_pending outcomes stay unknown even when pointer is old',t=>{
  const f=fixture(t);
  let j=begin(f);
  assert.equal(inspect(f).state,'unknown');
  assert.equal(inspect(f).observed,'previous');
  j=advance(f,j,'switch_pending',101);
  assert.equal(inspect(f).recordedPhase,'switch_pending');
  assert.equal(inspect(f).safeToReplay,false);
  assert.equal(readlinkSync(join(f.root,'current')),'versions/'+A);
});

test('switched pointer cannot become PASS without durable terminal health',t=>{
  const f=fixture(t);
  let j=begin(f);
  j=advance(f,j,'switch_pending',101);
  switchProtectedRelease(f.root,{expectedCommit:A,nextCommit:B,
    nextFiles:f.next.files});
  j=advance(f,j,'switched',102,{observedHashes:hashes(f.next.files)});
  const before=readFileSync(join(f.stateDir,ID+'.json'),'utf8');
  const result=inspect(f);
  assert.equal(result.state,'unknown');
  assert.equal(result.observed,'next');
  assert.equal(result.recordedPhase,'switched');
  assert.equal(result.requiresReconciliation,true);
  assert.equal(readFileSync(join(f.stateDir,ID+'.json'),'utf8'),before);
  assert.equal(readlinkSync(join(f.root,'current')),'versions/'+B);
});

test('durably verified healthy revision reads back without side effects',t=>{
  const f=fixture(t);
  let j=begin(f);
  j=advance(f,j,'switch_pending',101);
  switchProtectedRelease(f.root,{expectedCommit:A,nextCommit:B,
    nextFiles:f.next.files});
  j=advance(f,j,'switched',102,{observedHashes:hashes(f.next.files)});
  advance(f,j,'verified',103,{
    observedHashes:hashes(f.next.files),serviceHealthVerified:true
  });
  const result=inspect(f);
  assert.equal(result.state,'verified');
  assert.equal(result.observed,'next');
  assert.equal(result.requiresReconciliation,false);
  assert.equal(result.safeToReplay,false);
  // Reconciliation is not a mutation, nor a new journal operation.
  assert.deepEqual(readdirSync(f.stateDir),[ID+'.json']);
});

test('confirmed rollback is read back from old pointer',t=>{
  const f=fixture(t);
  let j=begin(f);
  j=advance(f,j,'switch_pending',101);
  switchProtectedRelease(f.root,{expectedCommit:A,nextCommit:B,
    nextFiles:f.next.files});
  j=advance(f,j,'switched',102,{observedHashes:hashes(f.next.files)});
  j=advance(f,j,'rollback_pending',103);
  switchProtectedRelease(f.root,{expectedCommit:B,nextCommit:A,
    nextFiles:f.old.files});
  advance(f,j,'rolled_back',104,{observedHashes:hashes(f.old.files)});
  const result=inspect(f);
  assert.equal(result.state,'rolled_back');
  assert.equal(result.observed,'previous');
  assert.equal(result.safeToReplay,false);
});

test('unknown marker never promotes old pointer to restart permission',t=>{
  const f=fixture(t);
  let j=begin(f);
  j=advance(f,j,'switch_pending',101);
  advance(f,j,'unknown',102);
  assert.equal(inspect(f).state,'unknown');
  assert.equal(inspect(f).safeToReplay,false);
});

test('confirmed previous state conflicts with unexpectedly switched pointer',t=>{
  const f=fixture(t);
  let j=begin(f);
  j=advance(f,j,'aborted',101);
  switchProtectedRelease(f.root,{expectedCommit:A,nextCommit:B,
    nextFiles:f.next.files});
  denied(()=>inspect(f));
});

test('terminal health verdict conflicts with old pointer and fails closed',t=>{
  const f=fixture(t);
  let j=begin(f);
  j=advance(f,j,'switch_pending',101);
  j=advance(f,j,'switched',102,{observedHashes:hashes(f.next.files)});
  advance(f,j,'verified',103,{
    observedHashes:hashes(f.next.files),serviceHealthVerified:true
  });
  denied(()=>inspect(f));
});

test('unexpected previous SHA or invalid operation identity is refused',t=>{
  const f=fixture(t);
  // A durable but incorrect previous release identity is not trusted
  // merely because the active pointer matches another installed version.
  begin(f,'f'.repeat(40));
  denied(()=>inspect(f));
  denied(()=>reconcileProtectedUpdateCandidate({
    root:f.root,stateDir:f.stateDir,operationId:'../bad'
  }));
});

function completeFirst(f,health=true){
  let j=begin(f);
  j=advance(f,j,'switch_pending',101);
  switchProtectedRelease(f.root,{expectedCommit:A,nextCommit:B,
    nextFiles:f.next.files});
  j=advance(f,j,'switched',102,{observedHashes:hashes(f.next.files)});
  if(health)advance(f,j,'verified',103,{
    observedHashes:hashes(f.next.files),serviceHealthVerified:true
  });
  else{
    j=advance(f,j,'rollback_pending',103);
    switchProtectedRelease(f.root,{expectedCommit:B,nextCommit:A,
      nextFiles:f.old.files});
    advance(f,j,'rolled_back',104,{observedHashes:hashes(f.old.files)});
  }
}
function beginSuccessor(f,{
  head=C,previousCommit=B,oldHashes=hashes(f.next.files),
  newHashes=hashes(f.third.files)
}={}){
  return beginStoredProtectedUpdateJournal(f.stateDir,{
    operationId:ID2,head,base:A,previousCommit,
    oldHashes,newHashes,nowMs:200
  });
}
function successorMove(f,j,to,nowMs,extra={}){
  return advanceStoredProtectedUpdateJournal(f.stateDir,ID2,{
    expectedSequence:j.sequence,to,nowMs,...extra
  });
}
test('verified A-to-B remains queryable after verified B-to-C',t=>{
  const f=fixture(t);
  completeFirst(f);
  let j=beginSuccessor(f);
  j=successorMove(f,j,'switch_pending',201);
  switchProtectedRelease(f.root,{expectedCommit:B,nextCommit:C,
    nextFiles:f.third.files});
  j=successorMove(f,j,'switched',202,{
    observedHashes:hashes(f.third.files)
  });
  successorMove(f,j,'verified',203,{
    observedHashes:hashes(f.third.files),serviceHealthVerified:true
  });
  const historical=inspect(f);
  assert.equal(historical.state,'verified');
  assert.equal(historical.observed,'superseded');
  assert.equal(historical.requiresReconciliation,false);
  assert.equal(historical.safeToReplay,false);
  const recent=reconcileProtectedUpdateCandidate({
    root:f.root,stateDir:f.stateDir,operationId:ID2
  });
  assert.equal(recent.state,'verified');
  assert.equal(recent.observed,'next');
});
test('earlier rollback stays queryable after a later successful revision',t=>{
  const f=fixture(t);
  completeFirst(f,false);
  let j=beginSuccessor(f,{
    head:B,previousCommit:A,
    oldHashes:hashes(f.old.files),
    newHashes:hashes(f.next.files)
  });
  j=successorMove(f,j,'switch_pending',201);
  switchProtectedRelease(f.root,{expectedCommit:A,nextCommit:B,
    nextFiles:f.next.files});
  j=successorMove(f,j,'switched',202,{
    observedHashes:hashes(f.next.files)
  });
  successorMove(f,j,'verified',203,{
    observedHashes:hashes(f.next.files),serviceHealthVerified:true
  });
  const historical=inspect(f);
  assert.equal(historical.state,'rolled_back');
  assert.equal(historical.observed,'superseded');
  assert.equal(historical.safeToReplay,false);
});
test('subsequent uncertain switch does not erase prior verified result',t=>{
  const f=fixture(t);
  completeFirst(f);
  let j=beginSuccessor(f);
  j=successorMove(f,j,'switch_pending',201);
  assert.equal(inspect(f).state,'verified');
  assert.equal(inspect(f).observed,'successor_unknown');
  assert.equal(inspect(f).requiresReconciliation,true);
  switchProtectedRelease(f.root,{expectedCommit:B,nextCommit:C,
    nextFiles:f.third.files});
  assert.equal(inspect(f).observed,'successor_unknown');
  assert.equal(inspect(f).safeToReplay,false);
});
test('unauthorized current pointer change without recorded successor is denied',t=>{
  const f=fixture(t);
  completeFirst(f);
  switchProtectedRelease(f.root,{expectedCommit:B,nextCommit:C,
    nextFiles:f.third.files});
  denied(()=>inspect(f));
});
test('disconnected or nonmonotonic successor is rejected before journal creation',t=>{
  const f=fixture(t);
  completeFirst(f);
  assert.throws(()=>beginSuccessor(f,{previousCommit:A}),
    /protected_journal_store_guard_failed/);
  assert.deepEqual(readdirSync(f.stateDir),[ID+'.json']);
});
test('active journal lock blocks history read instead of guessing success',t=>{
  const f=fixture(t);
  completeFirst(f);
  // A lock may represent an active or crashed writer; no stale lock removal.
  writeFileSync(join(f.stateDir,'.lock'),'active',{mode:0o600});
  denied(()=>inspect(f));
});
