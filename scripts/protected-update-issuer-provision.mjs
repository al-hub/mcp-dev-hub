// #35 ONE-TIME root-only, fixed-path provisioner CANDIDATE.
// It creates two separate minimal OS signing principals, each generating its
// OWN Ed25519 private key *after* dropping to its distinct uid/gid; the root
// process only receives/pins the two public keys. It NEVER signs approvals,
// installs sudoers, touches protected controller files or stores keys in Git.
//
// DO NOT run this from a checkout or before a complete independent security
// audit and explicit one-time owner administrator authorization. A failure
// after the first identity is created is an UNKNOWN partial provision, not
// something to blindly rerun or delete.
import {constants,closeSync,fstatSync,fsyncSync,lstatSync,mkdirSync,
  openSync,readFileSync,writeSync,chmodSync,chownSync,fchownSync,
  fchmodSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {createPublicKey,createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {resolve} from 'node:path';
import {verifyProtectedBootstrapPack}
  from './protected-update-bootstrap-pack.mjs';
import {assertFixedOperationalIssuerIsolation}
  from '../src/ops/protected-update-issuer-boundary.mjs';
import {parsePinnedBootstrapIssuerContext}
  from '../src/ops/protected-update-bootstrap-issuer.mjs';

const ROOT='/usr/local/lib/mcp-dev-hub';
const PACK=ROOT+'/protected-updater';
const ENTRY=PACK+'/code/scripts/protected-update-issuer-provision.mjs';
const BASE='/var/lib/mcp-dev-hub-signers';
const TRUST='/etc/mcp-dev-hub/protected-update';
const ROLES=Object.freeze([
  {role:'reviewer',user:'mcp35_reviewer'},
  {role:'approval',user:'mcp35_approver'}
]);
const READ=constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK;
const WRITE=constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|
  constants.O_NOFOLLOW;
const deny=()=>{throw Error('protected_issuer_provision_denied_or_unknown');};
const KEYGEN=String.raw`
const {generateKeyPairSync}=require('node:crypto');
const fs=require('node:fs');
const [dest]=process.argv.slice(1);
if(dest!=='/var/lib/mcp-dev-hub-signers/issuer-reviewer/private.ed25519.pem'&&
   dest!=='/var/lib/mcp-dev-hub-signers/issuer-approval/private.ed25519.pem')
  process.exit(50);
const {privateKey,publicKey}=generateKeyPairSync('ed25519');
const bytes=Buffer.from(privateKey.export({format:'pem',type:'pkcs8'}));
const fd=fs.openSync(dest,fs.constants.O_WRONLY|fs.constants.O_CREAT|
  fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o400);
try{
  let offset=0;
  while(offset<bytes.length){
    const n=fs.writeSync(fd,bytes,offset,bytes.length-offset,offset);
    if(n<=0)process.exit(51);
    offset+=n;
  }
  fs.fchmodSync(fd,0o400);
  fs.fsyncSync(fd);
}finally{fs.closeSync(fd);}
process.stdout.write(publicKey.export({format:'pem',type:'spki'}));
`;
export const PROTECTED_ISSUER_KEYGEN_PROGRAM=KEYGEN;
function dir(path,mode=null,owner=0){
  const s=lstatSync(path);
  if(!s.isDirectory()||s.isSymbolicLink()||s.uid!==owner||
     (s.mode&0o022)!==0||
     (mode!==null&&(s.mode&0o777)!==mode))deny();
}
function absent(path){
  try{lstatSync(path);deny();}catch(e){
    if(e.code!=='ENOENT')throw e;
  }
}
function syncDir(path){
  const fd=openSync(path,constants.O_RDONLY|constants.O_DIRECTORY|
    constants.O_NOFOLLOW);
  try{if(!fstatSync(fd).isDirectory())deny();fsyncSync(fd);}
  finally{closeSync(fd);}
}
function trust(name,maxBytes=4096,preserveExact=false){
  const fd=openSync(TRUST+'/'+name,READ);
  try{
    const s=fstatSync(fd);
    if(!s.isFile()||s.uid!==0||s.nlink!==1||
      (s.mode&0o777)!==0o400||s.size<1||s.size>maxBytes)deny();
    const b=readFileSync(fd);
    if(b.length!==s.size)deny();
    return decodeRootTrustBytes(b,preserveExact);
  }finally{closeSync(fd);}
}
function number(raw){
  if(typeof raw!=='string'||!/^[1-9][0-9]{0,8}$/.test(raw))deny();
  const n=Number(raw);
  if(!Number.isSafeInteger(n))deny();
  return n;
}
function systemAccount(name){
  const p=spawnSync('/usr/bin/getent',['passwd',name],{
    shell:false,encoding:'utf8',timeout:5000,maxBuffer:2048,
    env:{PATH:'/usr/bin:/bin'}
  });
  if(p.error||p.signal||p.status!==0)deny();
  const row=p.stdout.trim().split(':');
  if(row.length!==7||row[0]!==name)deny();
  const uid=number(row[2]),gid=number(row[3]);
  const g=spawnSync('/usr/bin/getent',['group',name],{
    shell:false,encoding:'utf8',timeout:5000,maxBuffer:2048,
    env:{PATH:'/usr/bin:/bin'}
  });
  if(g.error||g.signal||g.status!==0)deny();
  const fields=g.stdout.trim().split(':');
  if(fields.length!==4||fields[0]!==name||
     number(fields[2])!==gid)deny();
  return {uid,gid};
}
function requireMissingAccount(name){
  const p=spawnSync('/usr/bin/getent',['passwd',name],{
    shell:false,encoding:'utf8',timeout:5000,maxBuffer:1024,
    env:{PATH:'/usr/bin:/bin'}
  });
  if(p.error||p.signal||p.status!==2)deny();
}
function writeRootFile(name,value){
  const b=Buffer.from(String(value),'utf8');
  if(b.length<1||b.length>4096)deny();
  const fd=openSync(TRUST+'/'+name,WRITE,0o400);
  try{
    let n=0;
    while(n<b.length){
      const w=writeSync(fd,b,n,b.length-n,n);
      if(w<=0)deny();
      n+=w;
    }
    fsyncSync(fd);
    const s=fstatSync(fd);
    if(!s.isFile()||s.uid!==0||s.nlink!==1||
       (s.mode&0o777)!==0o400||s.size!==b.length)deny();
  }finally{closeSync(fd);}
}
// Root-only public reviewer key copy is the immutable approval issuer's
// read-only verification anchor. Root's private trust copy remains 0400.
// The two separately scoped read-only GitHub tokens are provided by the
// owner bootstrap and copied ONLY into the owning issuer's private directory.
function writePublicIssuerFile(name,value){
  const b=Buffer.from(String(value),'utf8');
  if(b.length<1||b.length>4096)deny();
  const fd=openSync(BASE+'/'+name,WRITE,0o444);
  try{
    writeSync(fd,b,0,b.length,0);
    // The owner umask can restrict 0444 at creation; enforce exact mode.
    fchmodSync(fd,0o444);
    fsyncSync(fd);
    const s=fstatSync(fd);
    if(!s.isFile()||s.uid!==0||s.nlink!==1||
       (s.mode&0o777)!==0o444||s.size!==b.length)deny();
  }finally{closeSync(fd);}
}
function copyIssuerReadonlyToken(role,uid,gid){
  const token=trust(role+'-github-readonly-token');
  if(!/^[a-zA-Z0-9_.-]{8,4096}$/.test(token))deny();
  const bytes=Buffer.from(token,'utf8');
  const path=BASE+'/issuer-'+role+'/github-readonly-token';
  const fd=openSync(path,WRITE,0o600);
  try{
    let n=0;
    while(n<bytes.length){
      const w=writeSync(fd,bytes,n,bytes.length-n,n);
      if(w<=0)deny();
      n+=w;
    }
    // No private token is made world-readable even during staging.
    fchownSync(fd,uid,gid);
    fchmodSync(fd,0o400);
    fsyncSync(fd);
    const s=fstatSync(fd);
    if(!s.isFile()||s.uid!==uid||s.gid!==gid||s.nlink!==1||
       (s.mode&0o777)!==0o400||s.size!==bytes.length)deny();
  }finally{closeSync(fd);}
}

/** Pure decoder for validated root-owned file bytes. Public keys must
 * retain the terminal newline; ordinary single-line settings are trimmed.
 */
export function decodeRootTrustBytes(bytes,preserveExact=false){
  if(!Buffer.isBuffer(bytes)||bytes.length<1||bytes.length>4096||
     typeof preserveExact!=='boolean')deny();
  const text=bytes.toString('utf8');
  return preserveExact?text:text.trim();
}
/** Before any privileged account/dir effect, require a canonical SPKI
 * PUBLIC PEM. createPublicKey(privatePem) otherwise accepts a private PEM
 * and would risk copying its original bytes into a world-readable file.
 */
export function requirePinnedCodexPublicKey(pem){
  if(typeof pem!=='string'||pem.length<60||pem.length>4096||
     !pem.startsWith('-----BEGIN PUBLIC KEY-----\n')||
     !pem.endsWith('-----END PUBLIC KEY-----\n')||
     pem.includes('PRIVATE KEY'))deny();
  let publicKey;
  try{publicKey=createPublicKey(pem);}catch{deny();}
  if(publicKey.asymmetricKeyType!=='ed25519')deny();
  const canonical=publicKey.export({type:'spki',format:'pem'});
  if(canonical!==pem)deny();
  return canonical;
}
/** Owner-pinned external gate attestor identities. These must be installed
 * from genuine independent device/root producers BEFORE any account creation,
 * not manufactured by the root provisioner or the AI coding Worker.
 */
export function verifyOwnerPinnedExternalGateKeys({
 devicePublicPem,rootPublicPem,codexPublicPem
}={}){
 const device=requirePinnedCodexPublicKey(devicePublicPem);
 const independentRoot=requirePinnedCodexPublicKey(rootPublicPem);
 const codex=requirePinnedCodexPublicKey(codexPublicPem);
 const der=p=>createPublicKey(p).export({type:'spki',format:'der'});
 if(der(device).equals(der(independentRoot))||
    der(device).equals(der(codex))||
    der(independentRoot).equals(der(codex)))deny();
 return Object.freeze({
  devicePublicPem:device,rootPublicPem:independentRoot,
  externallyProvisioned:true,privateKeysGenerated:false,
  installerAuthorized:false
 });
}
export function verifyRootSignerProvisionPlan({
  workerUid,workerGid,accountNames,rootPackVerified
}={}){
  if(!Number.isSafeInteger(workerUid)||workerUid<=0||
     !Number.isSafeInteger(workerGid)||workerGid<=0||
     rootPackVerified!==true||!Array.isArray(accountNames)||
     accountNames.length!==2||
     accountNames[0]!==ROLES[0].user||
     accountNames[1]!==ROLES[1].user)deny();
  return Object.freeze({phase:'provision_preflight_only',
    roles:2,noPrivateKeysDisclosed:true,
    bootstrapAuthorized:false});
}
/** No arguments, no dynamic identities or paths. Requires a package already
 * pinned by independent owner/admin digest and staged root-owned by an
 * independently reviewed administrative setup step.
 */
export function provisionIndependentProtectedIssuersOnce(){
  if(process.getuid?.()!==0||process.geteuid?.()!==0||
     process.argv.length!==2||fileURLToPath(import.meta.url)!==ENTRY)
    deny();
  for(const p of ['/','/usr','/usr/local','/usr/local/lib',ROOT,
    PACK,PACK+'/code',PACK+'/code/scripts','/etc',
    '/etc/mcp-dev-hub',TRUST,'/var','/var/lib'])
    dir(p);
  const digest=trust('approved-pack-digest',128);
  if(!/^[0-9a-f]{64}$/.test(digest))deny();
  const checked=verifyProtectedBootstrapPack({
    outputPath:PACK,expectedManifestSha256:digest
  });
  if(checked.status!=='source_only_unprivileged_no_go')deny();
  const workerUid=number(trust('worker-uid',16));
  const workerGid=number(trust('worker-gid',16));
  verifyRootSignerProvisionPlan({
    workerUid,workerGid,rootPackVerified:true,
    accountNames:ROLES.map(x=>x.user)
  });
  // All pre-existing role accounts/dirs/keys/public trust files are an
  // evidence-preserving BLOCKER. Never rotate or overwrite automatically.
  absent(BASE);
  for(const {role,user} of ROLES){
    requireMissingAccount(user);
    for(const name of [role+'-uid',role+'-gid',role+'-public.pem'])
      absent(TRUST+'/'+name);
  }
  // Root-side metadata inputs must already be pinned by the admin setup.
  if(!/^[0-9a-f]{40}$/.test(trust('baseline-commit',128))||
     !/^[0-9a-f]{40}$/.test(trust('approved-base-commit',128))||
     !/^[1-9][0-9]{0,14}$/.test(trust('approved-pr-number',48))||
     !/^[1-9][0-9]{0,14}$/.test(trust('approved-ci-run-id',48))||
     !/^[1-9][0-9]{0,14}$/.test(trust('reviewer-bot-id',48))||
     trust('github-token').length<8||
     trust('reviewer-github-readonly-token').length<8||
     trust('approval-github-readonly-token').length<8)deny();
  // Authenticate the independent Codex auditor public key BEFORE any
  // useradd or other OS side effect. This key must be pinned by the owner,
  // not generated by the reviewer/approval issuer.
  // Root-trust reader preserves exact PEM bytes with explicit raw option;
  // all other trust inputs retain the original whitespace-trimming behavior.
  const codexPublicPem=requirePinnedCodexPublicKey(
    trust('codex-reviewer-public.pem',4096,true));
  const codexPublicDer=createPublicKey(codexPublicPem)
    .export({type:'spki',format:'der'});
  // Two new external PUBLIC trust anchors must already be approved by the
  // owner. No key generation, account creation or other side effect occurs
  // until their identities are separately pinned and pairwise distinct.
  const external=verifyOwnerPinnedExternalGateKeys({
   devicePublicPem:trust('app-device-public.pem',4096,true),
   rootPublicPem:trust('app-root-public.pem',4096,true),
   codexPublicPem
  });
  const externalDers=[external.devicePublicPem,external.rootPublicPem]
    .map(p=>createPublicKey(p).export({type:'spki',format:'der'}));
  const identities=[];
  // NO root-owned private keys are generated: each issuer child receives a
  // fixed literal keygen program and drops to its own OS account identity.
  try{
    if(typeof process.setgroups!=='function')deny();
    process.setgroups([]);
  }catch{deny();}
  for(const {role,user} of ROLES){
    const add=spawnSync('/usr/sbin/useradd',[
      '--system','--user-group','--no-create-home',
      '--shell','/usr/sbin/nologin',user
    ],{shell:false,timeout:15000,maxBuffer:1024,
      env:{PATH:'/usr/sbin:/usr/bin:/sbin:/bin'},
      stdio:['ignore','pipe','pipe']});
    if(add.error||add.signal||add.status!==0)deny();
    const identity=systemAccount(user);
    if(identity.uid===workerUid||identity.gid===workerGid||
       identities.some(x=>x.uid===identity.uid||x.gid===identity.gid))
      deny();
    identities.push({...identity,role});
  }
  mkdirSync(BASE,{mode:0o755});chmodSync(BASE,0o755);
  dir(BASE,0o755);
  const pinnedContext={
    version:1,repository:'al-hub/mcp-dev-hub',
    scope:'protected-bootstrap',head:checked.head,
    base:trust('approved-base-commit',128),packDigest:digest,
    baselineCommit:trust('baseline-commit',128),
    baselineDigest:createHash('sha256').update(
      trust('baseline-files.json'),'utf8').digest('hex'),
    prNumber:Number(trust('approved-pr-number',48)),
    ciRunId:Number(trust('approved-ci-run-id',48)),
    reviewerBotId:Number(trust('reviewer-bot-id',48)),
    reviewerBotActor:'mcp-dev-hub-ai-reviewer[bot]'
  };
  parsePinnedBootstrapIssuerContext(JSON.stringify(pinnedContext));
  writePublicIssuerFile('approved-bootstrap-context.json',
    JSON.stringify(pinnedContext));
  writePublicIssuerFile('codex-reviewer-public.pem',codexPublicPem);
  // Stage only owner-approved PUBLIC key copies for the nonroot reviewer.
  // Actual signed gate receipts must be separately generated/authenticated;
  // this provisioner neither invents nor signs any device/root gate PASS.
  writePublicIssuerFile('app-device-public.pem',external.devicePublicPem);
  writePublicIssuerFile('app-root-public.pem',external.rootPublicPem);
  for(const {role,uid,gid} of identities){
    const dirPath=BASE+'/issuer-'+role;
    mkdirSync(dirPath,{mode:0o700});
    chownSync(dirPath,uid,gid);
    dir(dirPath,0o700,uid);
    const privatePath=dirPath+'/private.ed25519.pem';
    const created=spawnSync('/usr/bin/node',[
      '-e',KEYGEN,privatePath
    ],{uid,gid,shell:false,encoding:'utf8',timeout:15000,
      maxBuffer:4096,
      env:{PATH:'/usr/bin:/bin',LANG:'C'},
      stdio:['ignore','pipe','pipe']});
    if(created.error||created.signal||created.status!==0||
       typeof created.stdout!=='string'||created.stdout.length>2048)
      deny();
    const key=createPublicKey(created.stdout);
    if(key.asymmetricKeyType!=='ed25519'||
       key.export({type:'spki',format:'der'}).equals(codexPublicDer)||
       externalDers.some(k=>k.equals(
        key.export({type:'spki',format:'der'}))))deny();
    const keyInfo=lstatSync(privatePath);
    if(!keyInfo.isFile()||keyInfo.isSymbolicLink()||
       keyInfo.uid!==uid||keyInfo.gid!==gid||
       keyInfo.nlink!==1||(keyInfo.mode&0o777)!==0o400)deny();
    syncDir(dirPath);
    writeRootFile(role+'-public.pem',created.stdout);
    writeRootFile(role+'-uid',String(uid));
    writeRootFile(role+'-gid',String(gid));
    if(role==='reviewer')
      writePublicIssuerFile('reviewer-public.pem',created.stdout);
    if(role==='approval')
      writePublicIssuerFile('approval-public.pem',created.stdout);
    copyIssuerReadonlyToken(role,uid,gid);
  }
  syncDir(BASE);syncDir(TRUST);
  assertFixedOperationalIssuerIsolation();
  return Object.freeze({phase:'issuer_keys_provisioned_not_approved',
    distinctAccounts:2,
    privateKeysReturned:false,
    authorizationIssued:false,
    realProtectedUpdates:0,
    safeToRetry:false});
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  try{
    const result=provisionIndependentProtectedIssuersOnce();
    process.stdout.write(JSON.stringify(result)+'\n');
  }catch{
    process.stderr.write('protected_issuer_provision_denied_or_unknown\n');
    process.exitCode=1;
  }
}
