import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,mkdirSync,writeFileSync,chmodSync,readFileSync,rmSync,copyFileSync,symlinkSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';

test('AGY review result is collected; incomplete AGY attempt selects Codex next without false approval',()=>{
 const dir=mkdtempSync(join(tmpdir(),'cli-review-'));
 const resultDir=join(dir,'results');mkdirSync(resultDir);
 const bwrapLog=join(dir,'bwrap-args.log');
 const mockBwrap=join(dir,'mock-bwrap');
 writeFileSync(mockBwrap,'#!/bin/sh\nprintf "%s\\n" "$@" > '+JSON.stringify(bwrapLog)+'\nwhile [ "$#" -gt 0 ]; do\n if [ "$1" = "--" ]; then shift; exec "$@"; fi\n shift\ndone\nexit 97\n',{mode:0o700});
 chmodSync(mockBwrap,0o700);
 const mock=join(dir,'mock-cli');
 const mockSource='#!/bin/sh\ncase "$1" in --mode) echo "REVIEW_INCOMPLETE";; exec|run) echo "REVIEW_FINDINGS: no findings from inspected source";; *) exit 4;; esac\n';
 writeFileSync(mock,mockSource,{mode:0o700});chmodSync(mock,0o700);
 // Reviewer must see an independent, exact-HEAD clean repository; the
 // developer tree is intentionally dirty while tests run.
 const reviewed=join(dir,'exact-head');mkdirSync(reviewed);mkdirSync(join(reviewed,'scripts'));
 copyFileSync(join(process.cwd(),'scripts','worker.mjs'),join(reviewed,'scripts','worker.mjs'));
 const git=(...args)=>spawnSync('git',args,{cwd:reviewed,encoding:'utf8'});
 git('init','-q');git('config','user.email','ci@example.invalid');git('config','user.name','CI');
 git('add','.');git('commit','-qm','synthetic exact HEAD');
 const headSha=git('rev-parse','HEAD').stdout.trim();
 const run=(attempt)=>spawnSync(process.execPath,['scripts/review-opencode.mjs'],{
  cwd:process.cwd(),encoding:'utf8',timeout:10000,env:{
   ...process.env,MCP_DEV_HUB_REVIEW_JOB_ID:'review-test-001',
   MCP_DEV_HUB_REVIEW_RESULT_DIR:resultDir,MCP_DEV_HUB_REVIEW_ATTEMPT:String(attempt),
   MCP_DEV_HUB_REVIEW_SOURCE_DIR:reviewed,MCP_DEV_HUB_REVIEW_HEAD_SHA:headSha,
   MCP_DEV_HUB_BWRAP_BIN:mockBwrap,
   MCP_DEV_HUB_AGY_BIN:mock,MCP_DEV_HUB_CODEX_BIN:mock,MCP_DEV_HUB_OPENCODE_BIN:mock,
   MCP_DEV_HUB_REVIEW_AREA:'worker'
  }
 });
 try{
  const first=run(1);assert.equal(first.status,75,first.stderr);
  const a=JSON.parse(readFileSync(join(resultDir,'review-test-001-attempt-1.json')));
  assert.equal(a.provider,'agy');assert.equal(a.status,'failed');
  assert.equal(a.headSha,headSha);assert.equal(a.reviewIsolated,true);assert.equal(a.reviewReadonly,true);
  const bwrapArgs=readFileSync(bwrapLog,'utf8');
  assert.match(bwrapArgs,/--ro-bind/);assert.match(bwrapArgs,/\/review-src/);
  const second=run(2);assert.equal(second.status,0,second.stderr);
  const b=JSON.parse(readFileSync(join(resultDir,'review-test-001-attempt-2.json')));
  assert.equal(b.provider,'codex');assert.equal(b.status,'completed');
  assert.match(b.summary,/REVIEW_FINDINGS:/);
  const tertiary=spawnSync(process.execPath,['scripts/review-opencode.mjs'],{
   cwd:process.cwd(),encoding:'utf8',timeout:10000,
   env:{...process.env,MCP_DEV_HUB_REVIEW_JOB_ID:'review-test-001',
    MCP_DEV_HUB_REVIEW_RESULT_DIR:resultDir,MCP_DEV_HUB_REVIEW_ATTEMPT:'3',
    MCP_DEV_HUB_REVIEW_SOURCE_DIR:reviewed,MCP_DEV_HUB_REVIEW_HEAD_SHA:headSha,
    MCP_DEV_HUB_BWRAP_BIN:mockBwrap,
    MCP_DEV_HUB_AGY_BIN:mock,MCP_DEV_HUB_CODEX_BIN:mock,MCP_DEV_HUB_OPENCODE_BIN:mock,
    MCP_DEV_HUB_ENABLE_OPENCODE_FALLBACK:'1',MCP_DEV_HUB_REVIEW_AREA:'worker'}
  });
  assert.equal(tertiary.status,0,tertiary.stderr);
  assert.equal(JSON.parse(readFileSync(join(resultDir,'review-test-001-attempt-3.json'))).provider,'opencode');
 }finally{rmSync(dir,{recursive:true,force:true});}
});

test('review-opencode fails closed without trusted isolation, exact SHA, or clean read-only source mount',()=>{
 const dir=mkdtempSync(join(tmpdir(),'cli-review-neg-'));
 const resultDir=join(dir,'results');mkdirSync(resultDir);
 const mock=join(dir,'mock-cli');
 writeFileSync(mock,'#!/bin/sh\necho "REVIEW_FINDINGS: no findings"\n',{mode:0o700});chmodSync(mock,0o700);
 const headSha=spawnSync('git',['rev-parse','HEAD'],{cwd:process.cwd(),encoding:'utf8'}).stdout.trim();
 const baseEnv={
  ...process.env,MCP_DEV_HUB_REVIEW_JOB_ID:'review-neg-001',
  MCP_DEV_HUB_REVIEW_RESULT_DIR:resultDir,MCP_DEV_HUB_REVIEW_ATTEMPT:'1',
  MCP_DEV_HUB_REVIEW_SOURCE_DIR:process.cwd(),MCP_DEV_HUB_REVIEW_HEAD_SHA:headSha,
  MCP_DEV_HUB_AGY_BIN:mock,MCP_DEV_HUB_CODEX_BIN:mock,MCP_DEV_HUB_REVIEW_AREA:'worker'
 };
 try{
  // Missing bwrap binary -> fail closed, no fallback to direct spawn
  const noBwrap=spawnSync(process.execPath,['scripts/review-opencode.mjs'],{
   cwd:process.cwd(),encoding:'utf8',timeout:10000,
   env:{...baseEnv,MCP_DEV_HUB_BWRAP_BIN:join(dir,'missing-bwrap')}
  });
  assert.notEqual(noBwrap.status,0);
  // Stale/mismatched SHA -> fail closed before invoking reviewer
  const badSha=spawnSync(process.execPath,['scripts/review-opencode.mjs'],{
   cwd:process.cwd(),encoding:'utf8',timeout:10000,
   env:{...baseEnv,MCP_DEV_HUB_REVIEW_HEAD_SHA:'0'.repeat(40)}
  });
  assert.notEqual(badSha.status,0);
  // Missing source dir / SHA -> fail closed
  const noSource=spawnSync(process.execPath,['scripts/review-opencode.mjs'],{
   cwd:process.cwd(),encoding:'utf8',timeout:10000,
   env:{...baseEnv,MCP_DEV_HUB_REVIEW_SOURCE_DIR:''}
  });
  assert.notEqual(noSource.status,0);
 }finally{rmSync(dir,{recursive:true,force:true});}
});

test('committed source symlink to host-private file fails before reviewer CLI launch',()=>{
 const dir=mkdtempSync(join(tmpdir(),'review-symlink-'));
 const repo=join(dir,'exact-head'),priv=join(dir,'private-file'),bwrap=join(dir,'mock-bwrap'),cli=join(dir,'mock-cli');
 mkdirSync(repo);mkdirSync(join(repo,'scripts'));mkdirSync(join(dir,'results'));
 writeFileSync(priv,'SYNTHETIC_PRIVATE_CONTENT_DO_NOT_DISCLOSE\n');
 symlinkSync(priv,join(repo,'scripts','worker.mjs'));
 writeFileSync(bwrap,'#!/bin/sh\nwhile [ "$#" -gt 0 ]; do if [ "$1" = "--" ]; then shift;exec "$@";fi;shift;done\nexit 97\n',{mode:0o700});
 writeFileSync(cli,'#!/bin/sh\necho "REVIEW_FINDINGS: no findings"\n',{mode:0o700});
 const git=(...args)=>spawnSync('git',args,{cwd:repo,encoding:'utf8'});
 git('init','-q');git('config','user.email','ci@example.invalid');git('config','user.name','CI');
 git('add','.');git('commit','-qm','committed malicious symlink');
 const headSha=git('rev-parse','HEAD').stdout.trim();
 try{
  const run=spawnSync(process.execPath,['scripts/review-opencode.mjs'],{
   cwd:process.cwd(),encoding:'utf8',timeout:10000,
   env:{...process.env,MCP_DEV_HUB_REVIEW_JOB_ID:'review-symlink-001',
    MCP_DEV_HUB_REVIEW_RESULT_DIR:join(dir,'results'),MCP_DEV_HUB_REVIEW_ATTEMPT:'1',
    MCP_DEV_HUB_REVIEW_SOURCE_DIR:repo,MCP_DEV_HUB_REVIEW_HEAD_SHA:headSha,
    MCP_DEV_HUB_BWRAP_BIN:bwrap,MCP_DEV_HUB_AGY_BIN:cli,MCP_DEV_HUB_REVIEW_AREA:'worker'}
  });
  assert.notEqual(run.status,0);
  assert.doesNotMatch((run.stdout||'')+(run.stderr||''),/SYNTHETIC_PRIVATE_CONTENT_DO_NOT_DISCLOSE/);
 }finally{rmSync(dir,{recursive:true,force:true});}
});
