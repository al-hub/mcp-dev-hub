import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,mkdirSync,writeFileSync,chmodSync,readFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';

test('AGY review result is collected; incomplete AGY attempt selects Codex next without false approval',()=>{
 const dir=mkdtempSync(join(tmpdir(),'cli-review-'));
 const resultDir=join(dir,'results');mkdirSync(resultDir);
 const mock=join(dir,'mock-cli');
 const mockSource='#!/bin/sh\ncase "$1" in --mode) echo "REVIEW_INCOMPLETE";; exec) echo "REVIEW_FINDINGS: no findings from inspected source";; *) exit 4;; esac\n';
 writeFileSync(mock,mockSource,{mode:0o700});chmodSync(mock,0o700);
 const run=(attempt)=>spawnSync(process.execPath,['scripts/review-opencode.mjs'],{
  cwd:process.cwd(),encoding:'utf8',timeout:10000,env:{
   ...process.env,MCP_DEV_HUB_REVIEW_JOB_ID:'review-test-001',
   MCP_DEV_HUB_REVIEW_RESULT_DIR:resultDir,MCP_DEV_HUB_REVIEW_ATTEMPT:String(attempt),
   MCP_DEV_HUB_AGY_BIN:mock,MCP_DEV_HUB_CODEX_BIN:mock,
   MCP_DEV_HUB_REVIEW_AREA:'worker'
  }
 });
 try{
  const first=run(1);assert.equal(first.status,75,first.stderr);
  const a=JSON.parse(readFileSync(join(resultDir,'review-test-001-attempt-1.json')));
  assert.equal(a.provider,'agy');assert.equal(a.status,'failed');
  const second=run(2);assert.equal(second.status,0,second.stderr);
  const b=JSON.parse(readFileSync(join(resultDir,'review-test-001-attempt-2.json')));
  assert.equal(b.provider,'codex');assert.equal(b.status,'completed');
  assert.match(b.summary,/REVIEW_FINDINGS:/);
 }finally{rmSync(dir,{recursive:true,force:true});}
});
