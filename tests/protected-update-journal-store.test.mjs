import {spawnSync} from 'node:child_process';
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  chmodSync, mkdtempSync, readFileSync, rmSync, statSync, symlinkSync,
  unlinkSync, writeFileSync, renameSync
} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {
  beginStoredProtectedUpdateJournal, advanceStoredProtectedUpdateJournal,
  readStoredProtectedUpdateJournal
} from '../src/ops/protected-update-journal-store.mjs';
const idA='a'.repeat(32),idB='b'.repeat(32);
const oldHashes={
  'ai-github-canary-policy.mjs':'c'.repeat(64),
  'ai-github-canary.mjs':'c'.repeat(64)
};
const newHashes={
  'ai-github-canary-policy.mjs':'d'.repeat(64),
  'ai-github-canary.mjs':'d'.repeat(64)
};
const newerHashes={
  'ai-github-canary-policy.mjs':'e'.repeat(64),
  'ai-github-canary.mjs':'e'.repeat(64)
};
function tempState(t) {
  const dir=mkdtempSync(join(tmpdir(),'mcp-protected-state-'));
  chmodSync(dir,0o700);
  t.after(()=>rmSync(dir,{recursive:true,force:true}));
  return dir;
}
const args=(operationId=idA,old=oldHashes,next=newHashes,
  previousCommit='a'.repeat(40),head='f'.repeat(40))=>({
  operationId,head,base:'0'.repeat(40),previousCommit,
  oldHashes:old,newHashes:next,nowMs:1000
});
function move(dir,operationId,j,to,extra={}) {
  return advanceStoredProtectedUpdateJournal(dir,operationId,{
    expectedSequence:j.sequence,to,nowMs:1001+j.sequence,...extra
  });
}
test('fsynced journal readback tracks exact operation and two serial revisions',t=>{
  const dir=tempState(t);
  let j=beginStoredProtectedUpdateJournal(dir,args());
  assert.deepEqual(readStoredProtectedUpdateJournal(dir,idA),j);
  assert.equal(statSync(join(dir,idA+'.json')).mode&0o077,0);
  assert.equal(readStoredProtectedUpdateJournal(dir,idA).previousCommit,
    'a'.repeat(40));
  j=move(dir,idA,j,'switch_pending');
  assert.equal(j.sequence,1);
  j=move(dir,idA,j,'switched',{observedHashes:newHashes});
  j=move(dir,idA,j,'verified',{
    observedHashes:newHashes,serviceHealthVerified:true
  });
  assert.equal(readStoredProtectedUpdateJournal(dir,idA).phase,'verified');
  const second=beginStoredProtectedUpdateJournal(
    dir,args(idB,newHashes,newerHashes,'f'.repeat(40),'e'.repeat(40))
  );
  assert.equal(second.phase,'prepared');
  assert.equal(readStoredProtectedUpdateJournal(dir,idA).sequence,3);
  assert.equal(readStoredProtectedUpdateJournal(dir,idB).operationId,idB);
});
test('stale lock fails closed; never reclaims or retries a crashed writer',t=>{
  const dir=tempState(t);
  writeFileSync(join(dir,'.lock'),'stale',{mode:0o600});
  assert.throws(()=>beginStoredProtectedUpdateJournal(dir,args()));
  assert.equal(readFileSync(join(dir,'.lock'),'utf8'),'stale');
  assert.equal(readStoredProtectedUpdateJournal(dir,idA),null);
});
test('unknown state and duplicate operation IDs block new revisions',t=>{
  const dir=tempState(t);
  let j=beginStoredProtectedUpdateJournal(dir,args());
  assert.throws(()=>beginStoredProtectedUpdateJournal(dir,args()));
  j=move(dir,idA,j,'switch_pending');
  j=move(dir,idA,j,'unknown');
  assert.equal(readStoredProtectedUpdateJournal(dir,idA).phase,'unknown');
  assert.throws(()=>beginStoredProtectedUpdateJournal(
    dir,args(idB,newHashes,newerHashes)
  ));
  assert.throws(()=>move(dir,idA,j,'verified',{
    observedHashes:newHashes,serviceHealthVerified:true
  }));
});
test('stale sequence, incorrect file proof and skipped state are denied',t=>{
  const dir=tempState(t);
  const j=beginStoredProtectedUpdateJournal(dir,args());
  assert.throws(()=>move(dir,idA,j,'verified',{
    observedHashes:newHashes,serviceHealthVerified:true
  }));
  const pending=move(dir,idA,j,'switch_pending');
  assert.throws(()=>move(dir,idA,j,'switch_pending'));
  assert.throws(()=>move(dir,idA,pending,'switched',{
    observedHashes:oldHashes
  }));
  assert.equal(readStoredProtectedUpdateJournal(dir,idA).phase,'switch_pending');
});
test('unsafe journal bytes, file permissions and symlink are rejected',t=>{
  const dir=tempState(t);
  beginStoredProtectedUpdateJournal(dir,args());
  const file=join(dir,idA+'.json');
  chmodSync(file,0o644);
  assert.throws(()=>readStoredProtectedUpdateJournal(dir,idA));
  chmodSync(file,0o600);
  const raw=readFileSync(file,'utf8');
  writeFileSync(file,raw.replace('"version":2','"version":2,"version":2'));
  assert.throws(()=>readStoredProtectedUpdateJournal(dir,idA));
  unlinkSync(file);
  symlinkSync('nonexistent',file);
  assert.throws(()=>readStoredProtectedUpdateJournal(dir,idA));
});
test('leftover stage and unexpected state-dir entries are preserved and blocked',t=>{
  const dir=tempState(t);
  writeFileSync(join(dir,idA+'.tmp'),'partial',{mode:0o600});
  assert.throws(()=>beginStoredProtectedUpdateJournal(dir,args()));
  assert.equal(readFileSync(join(dir,idA+'.tmp'),'utf8'),'partial');
  assert.throws(()=>readStoredProtectedUpdateJournal(dir,'../escape'));
});
test('state directory symlink and permissive mode are rejected',t=>{
  const dir=tempState(t);
  const alias=dir+'-alias';
  symlinkSync(dir,alias);
  t.after(()=>unlinkSync(alias));
  assert.throws(()=>beginStoredProtectedUpdateJournal(alias,args()));
  chmodSync(dir,0o777);
  assert.throws(()=>beginStoredProtectedUpdateJournal(dir,args()));
});

test('journal filename must match canonical embedded operation ID',t=>{
  const dir=tempState(t);
  let j=beginStoredProtectedUpdateJournal(dir,args());
  j=move(dir,idA,j,'switch_pending');
  j=move(dir,idA,j,'switched',{observedHashes:newHashes});
  j=move(dir,idA,j,'verified',{
    observedHashes:newHashes,serviceHealthVerified:true
  });
  // Simulate a copied/misnamed durable record, without authorizing replay.
  renameSync(join(dir,idA+'.json'),join(dir,idB+'.json'));
  assert.throws(()=>readStoredProtectedUpdateJournal(dir,idB),
    /protected_journal_store_guard_failed/);
  assert.throws(()=>beginStoredProtectedUpdateJournal(dir,args(idA)),
    /protected_journal_store_guard_failed/);
  assert.equal(readStoredProtectedUpdateJournal(dir,idA),null);
});
test('journal-shaped FIFO fails closed before a blocking read',t=>{
  const dir=tempState(t);
  const fifo=join(dir,idA+'.json');
  const result=spawnSync('/usr/bin/mkfifo',[fifo],{timeout:2000});
  assert.equal(result.status,0);
  assert.throws(()=>readStoredProtectedUpdateJournal(dir,idA),
    /protected_journal_store_guard_failed/);
  assert.throws(()=>beginStoredProtectedUpdateJournal(
    dir,args(idB,newHashes,newerHashes)
  ),/protected_journal_store_guard_failed/);
});
