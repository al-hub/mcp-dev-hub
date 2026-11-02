import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,writeFileSync,chmodSync,readFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';

test('CLI smoke uses AGY first, Codex second, and OpenCode only when enabled',()=>{
 const d=mkdtempSync(join(tmpdir(),'cli-order-'));
 const log=join(d,'calls');
 const make=(name,response,code=0)=>{
  const path=join(d,name);
  writeFileSync(path,'#!/bin/sh\necho '+name+' >> '+JSON.stringify(log)+'\necho '+JSON.stringify(response)+'\nexit '+code+'\n',{mode:0o700});
  chmodSync(path,0o700);return path;
 };
 const agy=make('agy','not available',1),codex=make('codex','READY'),opencode=make('opencode','READY');
 const run=(env={})=>spawnSync(process.execPath,['scripts/cli-smoke.mjs'],{encoding:'utf8',timeout:15000,env:{...process.env,MCP_DEV_HUB_AGY_BIN:agy,MCP_DEV_HUB_CODEX_BIN:codex,MCP_DEV_HUB_OPENCODE_BIN:opencode,MCP_DEV_HUB_CLI_SMOKE_TIMEOUT_MS:'2000',...env}});
 try{
  const r=run();assert.equal(r.status,0,r.stderr);assert.deepEqual(readFileSync(log,'utf8').trim().split('\n'),['agy','codex']);
  writeFileSync(log,'');const r2=run({MCP_DEV_HUB_CODEX_BIN:agy,MCP_DEV_HUB_ENABLE_OPENCODE_FALLBACK:'1'});assert.equal(r2.status,0,r2.stderr);assert.deepEqual(readFileSync(log,'utf8').trim().split('\n'),['agy','agy','opencode']);
  writeFileSync(log,'');const r3=run({MCP_DEV_HUB_CODEX_BIN:agy});assert.equal(r3.status,1);assert.deepEqual(readFileSync(log,'utf8').trim().split('\n'),['agy','agy']);
 }finally{rmSync(d,{recursive:true,force:true});}
});
