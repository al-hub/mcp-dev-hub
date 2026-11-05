import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,mkdirSync,writeFileSync,symlinkSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {readBoundedModelOutput} from '../src/jobs/ai-github-canary-policy.mjs';
test('Model output is read only as a bounded regular file',()=>{
 const dir=mkdtempSync(join(tmpdir(),'mcp23-safe-output-'));
 try{
  const ok=join(dir,'verdict.txt');
  const data=JSON.stringify({verdict:'PASS',head:'a'.repeat(40),base:'b'.repeat(40),findings:[]});
  writeFileSync(ok,data);
  assert.equal(readBoundedModelOutput(ok),data);
  assert.throws(()=>readBoundedModelOutput(ok,12),/invalid_model_output_size_or_type/);
  const giant=join(dir,'giant.txt');
  writeFileSync(giant,'x'.repeat(6501));
  assert.throws(()=>readBoundedModelOutput(giant),/invalid_model_output_size_or_type/);
  const empty=join(dir,'empty.txt');
  writeFileSync(empty,'');
  assert.throws(()=>readBoundedModelOutput(empty),/invalid_model_output_size_or_type/);
  const symlink=join(dir,'alias');
  symlinkSync('/dev/zero',symlink);
  assert.throws(()=>readBoundedModelOutput(symlink));
  const folder=join(dir,'folder');
  mkdirSync(folder);
  assert.throws(()=>readBoundedModelOutput(folder),/invalid_model_output_size_or_type/);
 }finally{rmSync(dir,{recursive:true,force:true})}
});
