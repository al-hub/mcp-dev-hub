// #35: strict no-arguments ONE-SHOT BOOTSTRAP ENTRYPOINT CANDIDATE.
// Never run this from a checkout as root. An independently reviewed OS admin
// bootstrap must first copy a digest-pinned package into its fixed root-owned
// location, pin separate trusted issuers/baseline and review recovery.
// DOES NOT establish signer operational independence or install sudo policy.
import {constants,closeSync,fstatSync,lstatSync,openSync,readFileSync}
  from 'node:fs';
import {fileURLToPath} from 'node:url';
import {resolve} from 'node:path';
import {verifyProtectedBootstrapPack}
  from './protected-update-bootstrap-pack.mjs';
import {readRootProtectedUpdateTrust}
  from '../src/ops/protected-update-root-evidence.mjs';
import {migrateProtectedOriginalPairCandidate}
  from '../src/ops/protected-update-bootstrap-migration.mjs';

const ROOT='/usr/local/lib/mcp-dev-hub';
const PACK=ROOT+'/protected-updater';
const ENTRY=PACK+'/code/scripts/protected-update-bootstrap-entry.mjs';
const TRUST='/etc/mcp-dev-hub/protected-update';
const PACK_DIGEST=TRUST+'/approved-pack-digest';
const BASE_COMMIT=TRUST+'/baseline-commit';
const BASE_FILES=TRUST+'/baseline-files.json';
const WRAPPER=PACK+'/code/scripts/protected-update-controller-wrapper.mjs';
const SHA=/^[a-f0-9]{40}$/;
const HASH=/^[a-f0-9]{64}$/;
const NAMES=Object.freeze([
  'ai-github-canary-policy.mjs','ai-github-canary.mjs'
]);
const fail=()=>{throw Error('protected_bootstrap_entry_denied');};
const readFlags=constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK;
function dir(path,privateRoot=false){
  const st=lstatSync(path);
  if(!st.isDirectory()||st.isSymbolicLink()||st.uid!==0||
     (st.mode&0o022)!==0||
     (privateRoot&&(st.mode&0o777)!==0o700))fail();
}
function rootFile(path,maxBytes){
  const fd=openSync(path,readFlags);
  try{
    const st=fstatSync(fd);
    if(!st.isFile()||st.uid!==0||st.nlink!==1||
       (st.mode&0o777)!==0o400||
       st.size<1||st.size>maxBytes)fail();
    const bytes=readFileSync(fd);
    if(bytes.length!==st.size)fail();
    return bytes.toString('utf8');
  }finally{closeSync(fd);}
}
function parseBaseFiles(raw){
  let value;
  try{value=JSON.parse(raw);}catch{fail();}
  if(JSON.stringify(value)!==raw||!Array.isArray(value)||
     value.length!==2)fail();
  const result=[];
  for(let i=0;i<NAMES.length;i++){
    const f=value[i];
    if(!f||typeof f!=='object'||Array.isArray(f)||
       Object.keys(f).sort().join(',')!=='bytes,name,sha256'||
       f.name!==NAMES[i]||
       !Number.isSafeInteger(f.bytes)||f.bytes<1||f.bytes>256*1024||
       typeof f.sha256!=='string'||!HASH.test(f.sha256))fail();
    result.push(Object.freeze({...f}));
  }
  return Object.freeze(result);
}
/** As-built root OS read-only checks are done BEFORE any migration effect.
 * Signature issuers are required but operational issuer autonomy remains a
 * separate gate. Caller never supplies paths, SHA, stdin or executable args.
 */
export function bootstrapOneShotFixedRoot(){
  if(process.geteuid?.()!==0||process.getuid?.()!==0||
     process.argv.length!==2||fileURLToPath(import.meta.url)!==ENTRY)
    fail();
  for(const path of ['/', '/usr','/usr/local','/usr/local/lib',ROOT,
                      PACK,PACK+'/code',PACK+'/code/scripts'])
    dir(path,path===PACK||path===PACK+'/code'||
      path===PACK+'/code/scripts');
  for(const path of ['/', '/etc','/etc/mcp-dev-hub',TRUST])
    dir(path,path===TRUST);
  const pinned= rootFile(PACK_DIGEST,128).trim();
  const baselineCommit=rootFile(BASE_COMMIT,128).trim();
  const expectedLegacyFiles=parseBaseFiles(rootFile(BASE_FILES,4096));
  if(!HASH.test(pinned)||!SHA.test(baselineCommit))fail();
  // Root-held keys/token must be provisioned by independent identity setup.
  // The presence of two distinct public keys is NOT itself a security PASS.
  readRootProtectedUpdateTrust();
  const verified=verifyProtectedBootstrapPack({
    outputPath:PACK,expectedManifestSha256:pinned
  });
  // CRITICAL: source-only packages explicitly say installAuthorized=false.
  // Distinct public keys alone do not prove that either independent issuer
  // actually reviewed this exact install. Do not activate root migration
  // until a separate authenticated, pinned installer approval gate exists.
  if(verified.status!=='approved_for_one_shot')fail();
  const wrapperRow=verified.files.find(
    row=>row.path==='scripts/protected-update-controller-wrapper.mjs');
  if(!wrapperRow||!HASH.test(wrapperRow.sha256))fail();
  const wrapperBytes=readFileSync(WRAPPER);
  if(wrapperBytes.length!==wrapperRow.bytes)fail();
  if(verified.status!=='source_only_unprivileged_no_go')fail();
  return migrateProtectedOriginalPairCandidate({
    root:ROOT,baselineCommit,expectedLegacyFiles,
    wrapperBytes,wrapperSha256:wrapperRow.sha256
  });
}
// Direct invocation from a checkout is a hard failure, never a successful
// no-op. Imported modules (e.g. nonroot tests) perform no side effects.
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  try{
    const result=bootstrapOneShotFixedRoot();
    process.stdout.write(JSON.stringify({
      phase:result.phase,baselineCommit:result.baselineCommit,
      safeToRetry:false
    })+'\n');
  }catch{
    process.stderr.write('protected_bootstrap_entry_denied\n');
    process.exitCode=1;
  }
}
