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
  openSync,readFileSync,writeSync,chmodSync,chownSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {createPublicKey} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {resolve} from 'node:path';
import {verifyProtectedBootstrapPack}
  from './protected-update-bootstrap-pack.mjs';
import {assertFixedOperationalIssuerIsolation}
  from '../src/ops/protected-update-issuer-boundary.mjs';

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
if(typeof dest!=='string'||!/^\\/var\\/lib\\/mcp-dev-hub-signers\\/issuer-(?:reviewer|approval)\\/private\\.ed25519\\.pem$/.test(dest))
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
function trust(name,maxBytes=4096){
  const fd=openSync(TRUST+'/'+name,READ);
  try{
    const s=fstatSync(fd);
    if(!s.isFile()||s.uid!==0||s.nlink!==1||
      (s.mode&0o777)!==0o400||s.size<1||s.size>maxBytes)deny();
    const b=readFileSync(fd);
    if(b.length!==s.size)deny();
    return b.toString('utf8').trim();
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
     trust('github-token').length<8)deny();
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
    if(key.asymmetricKeyType!=='ed25519')deny();
    const keyInfo=lstatSync(privatePath);
    if(!keyInfo.isFile()||keyInfo.isSymbolicLink()||
       keyInfo.uid!==uid||keyInfo.gid!==gid||
       keyInfo.nlink!==1||(keyInfo.mode&0o777)!==0o400)deny();
    syncDir(dirPath);
    writeRootFile(role+'-public.pem',created.stdout);
    writeRootFile(role+'-uid',String(uid));
    writeRootFile(role+'-gid',String(gid));
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
