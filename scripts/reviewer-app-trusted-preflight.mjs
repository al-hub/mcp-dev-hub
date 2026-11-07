// #35 owner-staged root-only, READ-ONLY GitHub App authentication preflight.
// CANDIDATE SOURCE ONLY: never invoke as root from a checkout or directly
// from an unverified source package. Requires independent digest pinning and
// local owner installation into the exact root-owned fixed path first.
// This performs no review POST, signer issuance, sudo-policy or root update.
import {constants,openSync,fstatSync,closeSync,lstatSync,readFileSync,realpathSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {dirname} from 'node:path';
import {createAppJwt,readPrivateKey,createScopedAppClient}
  from '../src/jobs/github-app-review-publisher.mjs';

const ENTRY='/usr/local/lib/mcp-dev-hub/protected-updater/code/scripts/reviewer-app-trusted-preflight.mjs';
const CONFIG='/etc/mcp-dev-hub/reviewer-app-preflight.json';
const KEY_ROOT='/etc/mcp-dev-hub';
const KEY_PREFIX=KEY_ROOT+'/';
// Installed existing reviewer key is one level below its root-only parent.
// Support exactly a direct PEM leaf or one private root-owned subdirectory.
const KEY_LEAF=/^(?:[A-Za-z0-9_-]+\/)?[A-Za-z0-9_-][A-Za-z0-9._-]*\.pem$/;
const REPO='al-hub/mcp-dev-hub';
const REPO_ID=1440361577;
// Public App ID confirmed by the owning GitHub App's General settings.
const APP_ID=5576601;
const BOT='mcp-dev-hub-ai-reviewer[bot]';
const SHA=/^[a-f0-9]{40}$/;
const READ=constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK;
const deny=()=>{throw Error('trusted_app_preflight_denied');};

function trustedDirectory(path,privateDir=false){
 const s=lstatSync(path);
 if(!s.isDirectory()||s.isSymbolicLink()||s.uid!==0||
   (s.mode&0o022)!==0||(privateDir&&(s.mode&0o777)!==0o700))deny();
}
function trustedFile(path,mode,maxBytes){
 const fd=openSync(path,READ);
 try{
  const before=fstatSync(fd);
  if(!before.isFile()||before.uid!==0||before.nlink!==1||
    (before.mode&0o777)!==mode||before.size<1||
    before.size>maxBytes)deny();
  const data=readFileSync(fd);
  const after=fstatSync(fd);
  if(after.dev!==before.dev||after.ino!==before.ino||
    after.size!==before.size||data.length!==before.size)deny();
  return data.toString('utf8');
 }finally{closeSync(fd);}
}
function assertFixedRootInvocation(){
 if(process.getuid?.()!==0||process.geteuid?.()!==0||
   process.argv.length!==2||fileURLToPath(import.meta.url)!==ENTRY)deny();
 for(const p of ['/','/usr','/usr/local','/usr/local/lib',
   '/usr/local/lib/mcp-dev-hub',
   '/usr/local/lib/mcp-dev-hub/protected-updater',
   '/usr/local/lib/mcp-dev-hub/protected-updater/code',
   '/usr/local/lib/mcp-dev-hub/protected-updater/code/scripts',
   '/usr/local/lib/mcp-dev-hub/protected-updater/code/src',
   '/usr/local/lib/mcp-dev-hub/protected-updater/code/src/jobs',
   '/etc'])trustedDirectory(p);
 trustedDirectory('/etc/mcp-dev-hub',true);
 trustedFile(ENTRY,0o444,256*1024);
 trustedFile('/usr/local/lib/mcp-dev-hub/protected-updater/code/src/jobs/github-app-review-publisher.mjs',0o444,256*1024);
}
export function parseTrustedAppConfiguration(raw){
 if(typeof raw!=='string'||raw.length<40||raw.length>2048)deny();
 let c;
 try{c=JSON.parse(raw.trim());}catch{deny();}
 if(!c||typeof c!=='object'||Array.isArray(c)||
   Object.keys(c).sort().join(',')!=='appId,expectedHead,keyFile'||
   JSON.stringify(c)!==raw.trim()||
   !Number.isSafeInteger(c.appId)||c.appId!==APP_ID||
   typeof c.expectedHead!=='string'||!SHA.test(c.expectedHead)||
   typeof c.keyFile!=='string'||!c.keyFile.startsWith(KEY_PREFIX)||
   !KEY_LEAF.test(c.keyFile.slice(KEY_PREFIX.length)))deny();
 return Object.freeze(c);
}
async function getInstallation({appId,key,fetchImpl=fetch}){
 const jwt=createAppJwt({appId,privateKey:key});
 const url='https://api.github.com/repos/'+REPO+'/installation';
 const res=await fetchImpl(url,{
  method:'GET',
  headers:{Accept:'application/vnd.github+json',
   Authorization:'Bearer '+jwt,
   'X-GitHub-Api-Version':'2022-11-28'},
  signal:AbortSignal.timeout(12000)
 });
 if(!res?.ok)deny();
 const installation=await res.json();
 if(!Number.isSafeInteger(installation?.id)||installation.id<1||
   installation.app_id!==appId||
   installation.app_slug!=='mcp-dev-hub-ai-reviewer'||
   installation.account?.login!=='al-hub')deny();
 return installation.id;
}
// This helper can be unit-tested with synthetic inputs, but a synthetic
// "ready" value never authorizes a review or a root change.
export async function checkTrustedAppConnection({config,readKey=readPrivateKey,
 createClient=createScopedAppClient,installationLookup=getInstallation,
 readOwnedFile=trustedFile,validatePrivateDirectory=trustedDirectory}={}){
 try{
  const c=parseTrustedAppConfiguration(JSON.stringify(config));
  // Root-only private ancestors are checked before any key access.
  const keyParent=dirname(c.keyFile);
  if(keyParent!==KEY_ROOT)validatePrivateDirectory(keyParent,true);
  const keyInfo=readOwnedFile(c.keyFile,0o600,16384);
  const key=readKey(c.keyFile);
  if(typeof key!=='string'||key!==keyInfo)deny();
  const installationId=await installationLookup({appId:c.appId,key});
  const {actor,api}=await createClient({
   appId:c.appId,installationId,repositoryId:REPO_ID,key,prNumber:39
  });
  if(actor!==BOT)deny();
  const pr=await api('GET','/repos/'+REPO+'/pulls/39');
  if(pr?.number!==39||pr.state!=='open'||pr.draft!==false||
     pr.head?.sha!==c.expectedHead||pr.base?.ref!=='main'||
     pr.base?.repo?.full_name!==REPO||
     pr.user?.login!=='al-hub'||pr.user?.login===actor)deny();
  return Object.freeze({status:'ready',actor,prNumber:39,
   headSha:c.expectedHead,approvalSubmitted:false});
 }catch{
  return Object.freeze({status:'blocked',
   reason:'trusted_app_authentication_or_scope_unverified'});
 }
}
if(process.argv[1]&&fileURLToPath(import.meta.url)===process.argv[1]){
 try{
  assertFixedRootInvocation();
  const config=parseTrustedAppConfiguration(
   trustedFile(CONFIG,0o400,2048));
  const result=await checkTrustedAppConnection({config});
  process.stdout.write(JSON.stringify(result)+'\n');
  if(result.status!=='ready')process.exitCode=78;
 }catch{
  process.stdout.write(JSON.stringify({status:'blocked',
   reason:'trusted_app_authentication_or_scope_unverified'})+'\n');
  process.exitCode=78;
 }
}
