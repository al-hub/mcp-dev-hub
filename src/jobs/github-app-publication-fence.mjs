// #35 durable approval POST fence. No credentials, claims or PASS are created.
import {createHash} from 'node:crypto';
import {constants,closeSync,fstatSync,fsyncSync,lstatSync,openSync,
  writeFileSync} from 'node:fs';
const deny=()=>{throw Error('approval_publication_unknown_or_denied');};
const hash=x=>createHash('sha256').update(x).digest('hex');
/** Directory must be separately provisioned and inaccessible to the Worker.
 * Exclusive, fsynced intent survives timeout/restart and prevents POST replay.
 * A later invocation may only reconcile through the existing publisher GETs.
 */
export function fenceApprovalPost({api,directory,head,base,evidenceId,owner}={}){
 if(typeof api!=='function'||!/^\/[A-Za-z0-9_./-]+$/.test(directory||'')||
    directory.split('/').includes('..')||
    !/^[a-f0-9]{40}$/.test(head||'')||
    !/^[a-f0-9]{40}$/.test(base||'')||head===base||
    !/^verified-[a-z0-9-]{6,100}$/.test(evidenceId||'')||
    !Number.isSafeInteger(owner)||owner<0)deny();
 const st=lstatSync(directory);
 if(!st.isDirectory()||st.isSymbolicLink()||st.uid!==owner||
    (st.mode&0o777)!==0o700)deny();
 const expectedBody='AI-assisted independent Codex technical review (not a human review). Evidence: '+evidenceId;
 // A single HEAD/BASE is fenced even if a later caller changes evidence ID.
 const id=hash(head+':'+base);
 function durable(name,value){
  const fd=openSync(directory+'/'+id+name,constants.O_WRONLY|
   constants.O_CREAT|constants.O_EXCL|constants.O_NOFOLLOW,0o600);
  try{
   const s=fstatSync(fd);
   if(!s.isFile()||s.uid!==owner||s.nlink!==1||
      (s.mode&0o777)!==0o600)deny();
   writeFileSync(fd,JSON.stringify(value));
   fsyncSync(fd);
  }finally{closeSync(fd);}
  const dirfd=openSync(directory,constants.O_RDONLY|constants.O_DIRECTORY|
   constants.O_NOFOLLOW);
  try{fsyncSync(dirfd);}finally{closeSync(dirfd);}
 }
 return async(method,path,body)=>{
  if(method==='POST'&&path==='/repos/al-hub/mcp-dev-hub/pulls/39/reviews'){
   if(!body||Object.keys(body).sort().join(',')!=='body,commit_id,event'||
      body.commit_id!==head||body.event!=='APPROVE'||
      body.body!==expectedBody)deny();
   // Failure or a preexisting file is terminal; do not remove/retry it.
   durable('.intent.json',{version:1,head,base,evidenceId,
    bodySha256:hash(JSON.stringify(body)),state:'dispatched_or_unknown'});
   const result=await api(method,path,body);
   // Even a malformed response remains fenced. This is a receipt, not
   // confirmation; the caller must perform independent live readback.
   if(!Number.isSafeInteger(result?.id)||result.id<=0)deny();
   durable('.response.json',{version:1,reviewId:result.id,head,base,evidenceId});
   return result;
  }
  return api(method,path,body);
 };
}
