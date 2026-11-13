import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {generateKeyPairSync} from 'node:crypto';
import {readFileSync,mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {Script} from 'node:vm';
import {
  verifyRootSignerProvisionPlan,provisionIndependentProtectedIssuersOnce,
  requirePinnedCodexPublicKey,decodeRootTrustBytes,
  verifyOwnerPinnedExternalGateKeys,validatePinnedProtectedSignerMode,
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
test('independent public-key preflight rejects private PEM before 0444 copy',()=>{
  const signer=generateKeyPairSync('ed25519');
  const publicPem=signer.publicKey.export({type:'spki',format:'pem'});
  const privatePem=signer.privateKey.export({type:'pkcs8',format:'pem'});
  assert.equal(requirePinnedCodexPublicKey(publicPem),publicPem);
  for(const bad of [privatePem,publicPem.trim(),publicPem+'extra',
    publicPem.replace('PUBLIC KEY','PRIVATE KEY'),null,undefined,''])
    denied(()=>requirePinnedCodexPublicKey(bad));
  const rsa=generateKeyPairSync('rsa',{modulusLength:2048});
  denied(()=>requirePinnedCodexPublicKey(rsa.publicKey
    .export({type:'spki',format:'pem'})));
});
test('root public key trust reader preserves canonical PEM final newline',()=>{
  const publicPem=generateKeyPairSync('ed25519')
    .publicKey.export({type:'spki',format:'pem'});
  const raw=Buffer.from(publicPem);
  const actual=readFileSync(new URL(
    '../scripts/protected-update-issuer-provision.mjs',import.meta.url),'utf8');
  assert.match(actual,
    /trust\('codex-reviewer-public\.pem',4096,true\)/);
  assert.equal(decodeRootTrustBytes(raw,true),publicPem);
  assert.equal(requirePinnedCodexPublicKey(
    decodeRootTrustBytes(raw,true)),publicPem);
  assert.notEqual(decodeRootTrustBytes(raw,false),publicPem);
  denied(()=>requirePinnedCodexPublicKey(decodeRootTrustBytes(raw,false)));
  denied(()=>decodeRootTrustBytes(Buffer.alloc(0),true));
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

test('external proof key anchors are owner supplied, canonical, independently distinct',()=>{
 const keys=Array.from({length:4},()=>generateKeyPairSync('ed25519'));
 const pem=k=>k.publicKey.export({type:'spki',format:'pem'});
 const good={
  devicePublicPem:pem(keys[0]),
  rootPublicPem:pem(keys[1]),codexPublicPem:pem(keys[2])
 };
 const result=verifyOwnerPinnedExternalGateKeys(good);
 assert.equal(result.externallyProvisioned,true);
 assert.equal(result.privateKeysGenerated,false);
 assert.equal(result.installerAuthorized,false);
 for(const bad of [
  {...good,rootPublicPem:good.devicePublicPem},
  {...good,devicePublicPem:good.codexPublicPem},
  {...good,rootPublicPem:good.codexPublicPem},
  {...good,devicePublicPem:undefined},
  {...good,rootPublicPem:pem(keys[3]).trim()},
  {...good,codexPublicPem:keys[3].privateKey.export({
   type:'pkcs8',format:'pem'
  })}
 ])denied(()=>verifyOwnerPinnedExternalGateKeys(bad));
});
test('root provisioner must authenticate external keys before account creation',()=>{
 const source=readFileSync(new URL(
  '../scripts/protected-update-issuer-provision.mjs',import.meta.url),'utf8');
 const preflight=source.indexOf('const external=localMode?null:verifyOwnerPinnedExternalGateKeys(');
 const accounts=source.indexOf("spawnSync('/usr/sbin/useradd'");
 assert.ok(preflight>0&&accounts>preflight);
 assert.ok(source.includes(
  "writePublicIssuerFile('app-device-public.pem',external.devicePublicPem)"));
 assert.ok(source.includes(
  "writePublicIssuerFile('app-root-public.pem',external.rootPublicPem)"));
 assert.ok(source.includes(
  "writePublicIssuerFile('approval-public.pem',created.stdout)"));
});

test('owner-pinned signer mode is explicit and unknown modes refuse provision',()=>{
 assert.equal(validatePinnedProtectedSignerMode('wsl-local-v1'),'wsl-local-v1');
 assert.equal(validatePinnedProtectedSignerMode('external-v1'),'external-v1');
 for(const bad of ['',null,undefined,'legacy','Wsl-local-v1',
  'wsl-local-v1\n','external-v1\n',true])
  denied(()=>validatePinnedProtectedSignerMode(bad));
 const raw=readFileSync(new URL(
  '../scripts/protected-update-issuer-provision.mjs',import.meta.url),'utf8');
 assert.ok(raw.indexOf("trust('signer-mode',64)")>0);
 assert.ok(raw.indexOf("trust('signer-mode',64)")<
  raw.indexOf("spawnSync('/usr/sbin/useradd'"));
 assert.ok(raw.includes("if(!localMode){\n    writePublicIssuerFile('app-device-public.pem'"));
 assert.ok(raw.includes("writePublicIssuerFile('approved-local-bootstrap-context.json'"));
});

test('local Codex OS principal is inspected before any issuer account mutation',()=>{
 const src=readFileSync(new URL(
   '../scripts/protected-update-issuer-provision.mjs',import.meta.url),'utf8');
 const body=src.split('export function provisionIndependentProtectedIssuersOnce(){')[1];
 const start=body.indexOf('const localMode=');
 const lock=body.indexOf('mkdirSync(TOKEN_REFRESH_FENCE');
 const verify=body.indexOf('if(localMode)assertFixedCodexSignerPrerequisites()');
 const missing=body.indexOf('requireMissingAccount(user)');
 const tokens=body.indexOf("trust('reviewer-github-readonly-token')");
 const create=body.indexOf("spawnSync('/usr/sbin/useradd'");
 assert.ok(start>=0&&lock>start&&verify>lock&&missing>verify&&
   tokens>missing&&create>tokens);
 assert.ok(src.includes('assertFixedCodexSignerPrerequisites'));
});
