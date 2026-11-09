import test from 'node:test';
import assert from 'node:assert/strict';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {mkdtempSync,mkdirSync,existsSync,readFileSync,rmSync,writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';
import {parseRoutineDispatchFence,acquireRoutineDispatchFence,
 releaseTerminalRoutineDispatchFence,requireNoRoutineDispatchFence,
 probeDifferentInstalledHead}
 from '../src/ops/protected-update-routine-dispatch-fence.mjs';
import {PROTECTED_BOOTSTRAP_FILES}
 from '../scripts/protected-update-bootstrap-pack.mjs';
const ID='c'.repeat(32);
test('only exact active operation is a canonical non-replayable fence',()=>{
 const c=JSON.stringify({version:1,operationId:ID,
  state:'dispatched_or_unknown'});
 assert.equal(parseRoutineDispatchFence(c).operationId,ID);
 for(const changed of [
  c+' ',c.replace(ID,'../private'),c.replace('"version":1',
  '"version":2'),c.replace('dispatched_or_unknown','PASS')
 ])assert.throws(()=>parseRoutineDispatchFence(changed));
});
test('unprivileged checkout cannot acquire or remove protected fence',()=>{
 assert.throws(()=>acquireRoutineDispatchFence(ID));
 assert.throws(()=>requireNoRoutineDispatchFence());
 assert.throws(()=>releaseTerminalRoutineDispatchFence(ID,'verified'));
 assert.throws(()=>releaseTerminalRoutineDispatchFence(ID,'unknown'));
});
test('guard is part of exact fixed package; checkout root apply denied',()=>{
 assert.ok(PROTECTED_BOOTSTRAP_FILES.includes(
  'src/ops/protected-update-routine-dispatch-fence.mjs'));
 const path=fileURLToPath(new URL(
  '../scripts/protected-update-root-apply.mjs',import.meta.url));
 const result=spawnSync(process.execPath,[path],{
  input:JSON.stringify({version:2}),encoding:'utf8',
  timeout:5000,maxBuffer:1024
 });
 assert.equal(result.status,1);
 assert.equal(result.stdout,'');
});

/** Nonroot integration simulation: use the production fence implementation
 * unchanged except its fixed root gate and fixed OPS path, which are
 * deliberately remapped to an isolated test directory. No sudo/OS writes.
 */
async function simulatedFence(ops,{raceAfterAcquire=false}={}){
 const path=new URL('../src/ops/protected-update-routine-dispatch-fence.mjs',
  import.meta.url);
 let src=readFileSync(path,'utf8');
 const rootPath="const OPS='/var/lib/mcp-dev-hub-signers/routine-operations';";
 assert.equal(src.split(rootPath).length,2);
 src=src.replace(rootPath,'const OPS='+JSON.stringify(ops)+';');
 const guard=/function root\(\)\{[\s\S]*?\n\}\nfunction directorySync\(\)/;
 assert.match(src,guard);
 src=src.replace(guard,'function root() {}\nfunction directorySync()');
 // In this test-only remap, the unprivileged caller owns the temporary
 // lock file; production root-file UID validation is NOT changed.
 src=src.replaceAll('s.uid!==0','s.uid!==process.getuid()');
 if(raceAfterAcquire){
  const start='function slotAbsent(operationId){';
  assert.equal(src.split(start).length,2);
  // Only the scheduling result of the first pre-lock lookup is faked.
  // All actual file syscalls, lock writes, fsync and cleanup remain intact.
  src=src.replace(start,`let firstSlotCheck=true;
function slotAbsent(operationId){
 if(firstSlotCheck){firstSlotCheck=false;return true;}`);
 }
 const fixtureFile=join(ops,'..','fixture-fence-'+
  (raceAfterAcquire?'race':'replay')+'.mjs');
 writeFileSync(fixtureFile,src,{mode:0o600});
 return await import(pathToFileURL(fixtureFile).href);
}
test('replayed completed routine slot is rejected without poisoning global fence',async()=>{
 const tmp=mkdtempSync(join(tmpdir(),'mcp35-routine-lock-'));
 const ops=join(tmp,'routine-operations'),next='d'.repeat(32);
 try{
  mkdirSync(ops,{mode:0o755});
  const f=await simulatedFence(ops);
  mkdirSync(join(ops,ID),{mode:0o700});
  assert.throws(()=>f.acquireRoutineDispatchFence(ID,{validateCandidate:()=>true}),
   /routine_dispatch_unknown_or_denied/);
  assert.equal(existsSync(join(ops,'.active-routine')),false);
  assert.equal(f.acquireRoutineDispatchFence(next,{validateCandidate:()=>true}).operationId,next);
  assert.equal(existsSync(join(ops,'.active-routine')),true);
  f.releaseTerminalRoutineDispatchFence(next,'verified');
  assert.equal(existsSync(join(ops,'.active-routine')),false);
 }finally{rmSync(tmp,{recursive:true,force:true});}
});
test('old routine slot appearing between precheck and acquisition releases only fresh lock',async()=>{
 const tmp=mkdtempSync(join(tmpdir(),'mcp35-routine-race-'));
 const ops=join(tmp,'routine-operations');
 try{
  mkdirSync(ops,{mode:0o755});
  mkdirSync(join(ops,ID),{mode:0o700});
  const f=await simulatedFence(ops,{raceAfterAcquire:true});
  assert.throws(()=>f.acquireRoutineDispatchFence(ID,{validateCandidate:()=>true}),
   /routine_dispatch_unknown_or_denied/);
  assert.equal(existsSync(join(ops,'.active-routine')),false);
 }finally{rmSync(tmp,{recursive:true,force:true});}
});

test('installed target identity checks deny unknown and preinstalled SHA',()=>{
 const old='a'.repeat(40),target='b'.repeat(40);
 assert.equal(probeDifferentInstalledHead({installedCommit:old,requestedHead:target}),true);
 assert.equal(probeDifferentInstalledHead({installedCommit:target,requestedHead:target}),false);
 for(const invalid of [{},{installedCommit:'bad',requestedHead:target},
  {installedCommit:old,requestedHead:'wrong'}])
  assert.throws(()=>probeDifferentInstalledHead(invalid),
   /routine_dispatch_unknown_or_denied/);
});
test('no-op appearing after lock acquisition releases only this new pre-dispatch lock',async()=>{
 const tmp=mkdtempSync(join(tmpdir(),'mcp35-routine-noop-'));
 const ops=join(tmp,'routine-operations');
 try{
  mkdirSync(ops,{mode:0o755});
  const f=await simulatedFence(ops);
  let calls=0;
  assert.throws(()=>f.acquireRoutineDispatchFence(ID,{
   validateCandidate:()=>++calls===1
  }),/routine_dispatch_unknown_or_denied/);
  assert.equal(calls,2);
  assert.equal(existsSync(join(ops,'.active-routine')),false);
  assert.equal(existsSync(join(ops,ID)),false);
  const next='e'.repeat(32);
  assert.equal(f.acquireRoutineDispatchFence(next,{validateCandidate:()=>true}).operationId,next);
  f.releaseTerminalRoutineDispatchFence(next,'verified');
 }finally{rmSync(tmp,{recursive:true,force:true});}
});
test('unknown installed snapshot after lock acquisition retains global fence',async()=>{
 const tmp=mkdtempSync(join(tmpdir(),'mcp35-routine-unknown-'));
 const ops=join(tmp,'routine-operations');
 try{
  mkdirSync(ops,{mode:0o755});
  const f=await simulatedFence(ops);
  let calls=0;
  assert.throws(()=>f.acquireRoutineDispatchFence(ID,{
   validateCandidate:()=>{if(++calls===2)throw Error('unknown_current_pointer');return true;}
  }),/unknown_current_pointer/);
  assert.equal(existsSync(join(ops,'.active-routine')),true);
  assert.equal(existsSync(join(ops,ID)),false);
  assert.throws(()=>f.requireNoRoutineDispatchFence(),
   /routine_dispatch_unknown_or_denied/);
 }finally{rmSync(tmp,{recursive:true,force:true});}
});
test('fixed stage and root apply independently check installed head before signer dispatch',()=>{
 const stage=readFileSync(new URL('../src/ops/protected-update-routine-stage.mjs',import.meta.url),'utf8');
 const apply=readFileSync(new URL('../scripts/protected-update-root-apply.mjs',import.meta.url),'utf8');
 assert.ok(stage.includes('acquireRoutineDispatchFence(c.operationId,{validateCandidate:()=>'));
 assert.ok(stage.includes('installedCommit:inspectProtectedCurrentSnapshot(ROOT).commit'));
 assert.ok(apply.indexOf('if(!probeDifferentInstalledHead({')<
  apply.indexOf('const collected=await collectFixedRoutineIssuerAttestations({intent})'));
});
