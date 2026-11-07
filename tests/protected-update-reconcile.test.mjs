import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {
  chmodSync,mkdirSync,mkdtempSync,readFileSync,readlinkSync,
  readdirSync,rmSync
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

const A='a'.repeat(40),B='b'.repeat(40),ID='c'.repeat(32);
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
  const old=makeFiles('A'),next=makeFiles('B');
  stageProtectedRelease(root,{commit:A,...old});
  stageProtectedRelease(root,{commit:B,...next});
  switchProtectedRelease(root,{
    expectedCommit:null,nextCommit:A,nextFiles:old.files
  });
  t.after(()=>{
    for(const name of readdirSync(join(root,'versions'))){
      chmodSync(join(root,'versions',name),0o700);
    }
    rmSync(top,{recursive:true,force:true});
  });
  return {root,stateDir,old,next};
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
