import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {readFileSync,mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {Script} from 'node:vm';
import {
  verifyRootSignerProvisionPlan,provisionIndependentProtectedIssuersOnce,
  PROTECTED_ISSUER_KEYGEN_PROGRAM
} from '../scripts/protected-update-issuer-provision.mjs';
import {PROTECTED_BOOTSTRAP_FILES}
  from '../scripts/protected-update-bootstrap-pack.mjs';
const denied=fn=>assert.throws(fn,
  /protected_issuer_provision_denied_or_unknown/);
const fixture=()=>({
  workerUid:1000,workerGid:1000,rootPackVerified:true,
  accountNames:['mcp35_reviewer','mcp35_approver']
});
test('two distinct roles are pinned and provisioning never signs authorization',()=>{
  const x=verifyRootSignerProvisionPlan(fixture());
  assert.equal(x.roles,2);
  assert.equal(x.phase,'provision_preflight_only');
  assert.equal(x.noPrivateKeysDisclosed,true);
  assert.equal(x.bootstrapAuthorized,false);
});
test('cannot provision with root Worker or shared missing identity',()=>{
  for(const bad of [
    {...fixture(),workerUid:0},
    {...fixture(),workerGid:0},
    {...fixture(),rootPackVerified:false},
    {...fixture(),accountNames:['same','same']},
    {...fixture(),accountNames:['mcp35_reviewer','root']},
    {...fixture(),accountNames:[]},
    {}
  ])denied(()=>verifyRootSignerProvisionPlan(bad));
});
test('provision candidate is included in immutable, pinned source bundle',()=>{
  assert.ok(PROTECTED_BOOTSTRAP_FILES.includes(
    'scripts/protected-update-issuer-provision.mjs'));
});
test('untrusted checkout cannot provision system identities or signing keys',()=>{
  denied(()=>provisionIndependentProtectedIssuersOnce());
});
test('direct root-setup script invocation from checkout is blocked',()=>{
  const src=fileURLToPath(new URL(
    '../scripts/protected-update-issuer-provision.mjs',import.meta.url));
  const r=spawnSync(process.execPath,[src],{
    encoding:'utf8',timeout:5000,maxBuffer:4096
  });
  assert.equal(r.status,1);
  assert.match(r.stderr,
    /protected_issuer_provision_denied_or_unknown/);
  assert.equal(r.stdout,'');
});

test('literal keygen child code parses but cannot write to arbitrary path',()=>{
  assert.doesNotThrow(()=>new Script(PROTECTED_ISSUER_KEYGEN_PROGRAM));
  const r=spawnSync(process.execPath,[
    '-e',PROTECTED_ISSUER_KEYGEN_PROGRAM,'/tmp/unsafe-key-target'
  ],{encoding:'utf8',timeout:5000,maxBuffer:1024});
  assert.equal(r.status,50);
  assert.equal(r.stdout,'');
});

test('privileged token copier imports fchmodSync before any account effects',()=>{
  const source=readFileSync(new URL(
    '../scripts/protected-update-issuer-provision.mjs',import.meta.url),'utf8');
  const fsImport=source.match(/import\s*\{([^}]*)\}\s*from\s*'node:fs';/);
  assert.ok(fsImport);
  assert.ok(fsImport[1].split(',').map(s=>s.trim()).includes('fchmodSync'));
});

test('public issuer writer enforces exact mode despite restrictive admin umask',()=>{
  const source=readFileSync(new URL(
    '../scripts/protected-update-issuer-provision.mjs',import.meta.url),'utf8');
  const writer=source.split('function writePublicIssuerFile(name,value){')[1]
    ?.split('function copyIssuerReadonlyToken(')[0];
  assert.ok(writer);
  assert.ok(writer.includes('fchmodSync(fd,0o444);'));
  assert.ok(writer.indexOf('fchmodSync(fd,0o444)')<
    writer.indexOf('fsyncSync(fd)'));
  const dir=mkdtempSync(join(tmpdir(),'mcp35-issuer-mode-'));
  const childCode=String.raw`const fs=require('node:fs');
process.umask(Number(process.argv[2]));
const fd=fs.openSync(process.argv[1],fs.constants.O_WRONLY|
  fs.constants.O_CREAT|fs.constants.O_EXCL,0o444);
try{fs.writeSync(fd,'synthetic');fs.fchmodSync(fd,0o444);
  fs.fsyncSync(fd);process.stdout.write(String(fs.fstatSync(fd).mode&0o777));}
finally{fs.closeSync(fd);}`;
  try{
    for(const umask of [0o027,0o077]){
      const r=spawnSync(process.execPath,[
        '-e',childCode,join(dir,'issuer-'+umask),String(umask)
      ],{encoding:'utf8',timeout:5000,maxBuffer:1024});
      assert.equal(r.status,0,r.stderr);
      assert.equal(r.stdout,String(0o444));
    }
  }finally{rmSync(dir,{recursive:true,force:true});}
});
