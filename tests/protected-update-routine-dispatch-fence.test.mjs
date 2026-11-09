import test from 'node:test';
import assert from 'node:assert/strict';
import {fileURLToPath} from 'node:url';
import {spawnSync} from 'node:child_process';
import {parseRoutineDispatchFence,acquireRoutineDispatchFence,
 releaseTerminalRoutineDispatchFence,requireNoRoutineDispatchFence}
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
