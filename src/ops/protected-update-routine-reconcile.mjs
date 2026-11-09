// #35 fixed root-only, read-only reconciliation of routine issuer attempts.
// A staging slot is an irreversible attempt fence: it is NEVER replay
// authority. Absence of a transaction journal does NOT imply no signer ran.
import {createHash} from 'node:crypto';
import {constants,closeSync,fstatSync,lstatSync,openSync,
  readFileSync,readdirSync} from 'node:fs';
import {parsePinnedRoutineIssuerContext}
  from './protected-update-routine-issuer.mjs';
import {parseProtectedUpdateRequest}
  from './protected-update-request.mjs';
const ROOT='/var/lib/mcp-dev-hub-signers';
const OPS=ROOT+'/routine-operations';
const ID=/^[a-f0-9]{32}$/;
const deny=()=>{throw Error('protected_routine_reconcile_denied');};
const hash=s=>createHash('sha256').update(s).digest('hex');
const REQUIRED=new Set([
 'approved-routine-context.json','codex-review.json','codex-review.sig',
 'codex-reviewer-public.pem','reviewer-public.pem','dispatch.intent.json',
 'routine-review-handoff.json','routine-approval.json',
 'routine-approval.sig','approved-request.json','issuance-complete.json'
]);
function directory(path,mode=null){
 const s=lstatSync(path);
 if(!s.isDirectory()||s.isSymbolicLink()||s.uid!==0||
    (s.mode&0o022)!==0||
    (mode!==null&&(s.mode&0o777)!==mode))deny();
}
function readOnce(path,mode,max){
 const fd=openSync(path,constants.O_RDONLY|constants.O_NOFOLLOW|
  constants.O_NONBLOCK);
 try{
  const s=fstatSync(fd);
  if(!s.isFile()||s.uid!==0||s.nlink!==1||
     (s.mode&0o777)!==mode||s.size<1||s.size>max)deny();
  const value=readFileSync(fd);
  if(value.length!==s.size)deny();
  return value.toString('utf8');
 }finally{closeSync(fd);}
}
const exact=(o,keys)=>o&&typeof o==='object'&&!Array.isArray(o)&&
 Object.keys(o).sort().join(',')===keys.slice().sort().join(',');
/** Pure synthetic classification, not filesystem authority. Only exact
 * known file names are accepted, never a Worker-supplied status string.
 */
export function classifyRoutineIssuerArtifacts({
 operationId,files,contextRaw,requestRaw,completionRaw
}={}){
 if(!ID.test(operationId||'')||!Array.isArray(files)||
    files.length!==new Set(files).size||
    files.some(f=>!REQUIRED.has(f)))deny();
 const found=new Set(files);
 if(!found.has('issuance-complete.json')){
  // Even an empty/partially written directory can mean a dispatched job.
  return Object.freeze({operationId,state:'issuance_unknown',
   safeToReplay:false,requiresReconciliation:true});
 }
 const complete=[
  'approved-routine-context.json','codex-review.json','codex-review.sig',
  'codex-reviewer-public.pem','reviewer-public.pem',
  'dispatch.intent.json','routine-review-handoff.json',
  'routine-approval.json','routine-approval.sig',
  'approved-request.json','issuance-complete.json'
 ];
 if(!complete.every(f=>found.has(f))||files.length!==complete.length)
  deny();
 let context,request,done;
 try{
  context=parsePinnedRoutineIssuerContext(contextRaw);
  request=parseProtectedUpdateRequest(requestRaw);
  done=JSON.parse(completionRaw);
 }catch{deny();}
 if(!exact(done,['version','operationId','requestSha256','phase',
    'safeToReplay'])||
    JSON.stringify(done)!==completionRaw||done.version!==1||
    done.operationId!==operationId||
    done.phase!=='both_signed_pending_root_apply'||
    done.safeToReplay!==false||
    done.requestSha256!==hash(requestRaw)||
    context.operationId!==operationId||
    request.operationId!==operationId||
    context.head!==request.head||context.base!==request.base||
    context.manifestJson!==request.manifestJson||
    context.ciRunId!==request.ciRunId||
    context.prNumber!==request.prNumber)deny();
 return Object.freeze({operationId,state:'issued_pending_or_unknown_apply',
  safeToReplay:false,requiresReconciliation:true});
}
/** Called ONLY by an installed fixed root reconcile entrypoint after
 * validating the existing protected OS layout. Never exposes request bytes.
 */
export function inspectFixedRoutineIssuerOperation(operationId){
 if(process.getuid?.()!==0||process.geteuid?.()!==0||
    !ID.test(operationId||''))deny();
 for(const p of ['/','/var','/var/lib',ROOT])directory(p);
 let os;
 try{os=lstatSync(OPS);}catch(e){
  if(e.code==='ENOENT')return Object.freeze({
   operationId,state:'not_staged',safeToReplay:false,
   requiresReconciliation:true
  });
  throw e;
 }
 if(!os.isDirectory()||os.isSymbolicLink()||os.uid!==0||
    (os.mode&0o777)!==0o755)deny();
 const slot=OPS+'/'+operationId;
 let st;
 try{st=lstatSync(slot);}catch(e){
  if(e.code==='ENOENT')return Object.freeze({
   operationId,state:'not_staged',safeToReplay:false,
   requiresReconciliation:true
  });
  throw e;
 }
 if(!st.isDirectory()||st.isSymbolicLink()||st.uid!==0||
    ![0o700,0o755].includes(st.mode&0o777))deny();
 const names=readdirSync(slot);
 if(names.length>REQUIRED.size||names.some(n=>!REQUIRED.has(n)))deny();
 const has=new Set(names);
 const raw=(name,mode,limit)=>has.has(name)
  ?readOnce(slot+'/'+name,mode,limit):undefined;
 const state=classifyRoutineIssuerArtifacts({
  operationId,files:names,
  contextRaw:raw('approved-routine-context.json',0o444,6500),
  requestRaw:raw('approved-request.json',0o400,16000),
  completionRaw:raw('issuance-complete.json',0o400,2000)
 });
 if(readdirSync(slot).slice().sort().join(',')!==
    names.slice().sort().join(','))deny();
 return state;
}
