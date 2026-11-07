// #35 immutable root-side operation-ID result lookup, read-only candidate.
// Never grants replay, deletes a lock, changes a pointer, or guesses success.
// A future one-time owner-reviewed bootstrap must pin this fixed code and a
// narrow no-arguments invocation; never run checkout source as root.
import {fileURLToPath} from 'node:url';
import {resolve} from 'node:path';
import {assertFixedRootProtectedUpdateLayout}
  from '../src/ops/protected-update-root-layout.mjs';
import {reconcileProtectedUpdateCandidate}
  from '../src/ops/protected-update-reconcile.mjs';

const SELF='/usr/local/lib/mcp-dev-hub/protected-updater/code/scripts/protected-update-root-reconcile.mjs';
const ROOT='/usr/local/lib/mcp-dev-hub';
const STATE='/var/lib/mcp-dev-hub/protected-update';
const ID=/^[a-f0-9]{32}$/;
const deny=()=>{throw Error('protected_root_reconcile_denied');};
function readOperationId(){
  return new Promise((resolveId,reject)=>{
    let done=false,size=0,buf='';
    const timeout=setTimeout(()=>finish(Error('protected_root_reconcile_timeout')),5000);
    function finish(err){
      if(done)return;
      done=true;clearTimeout(timeout);
      process.stdin.off('data',onData);
      process.stdin.off('end',onEnd);
      process.stdin.off('error',onError);
      process.stdin.pause();
      if(err)reject(err);
      else resolveId(buf.trim());
    }
    function onData(chunk){
      size+=chunk.length;
      if(size>34){finish(Error('protected_root_reconcile_oversized'));return;}
      buf+=chunk.toString('utf8');
    }
    function onEnd(){finish();}
    function onError(){finish(Error('protected_root_reconcile_transport'));}
    process.stdin.on('data',onData);
    process.stdin.on('end',onEnd);
    process.stdin.on('error',onError);
    process.stdin.resume();
  });
}
export async function reconcileOneProtectedUpdateFixedRoot(){
  if(process.geteuid?.()!==0||process.getuid?.()!==0||
     fileURLToPath(import.meta.url)!==SELF||process.argv.length!==2)
    deny();
  const operationId=await readOperationId();
  if(!ID.test(operationId))deny();
  assertFixedRootProtectedUpdateLayout();
  const result=reconcileProtectedUpdateCandidate({
    root:ROOT,stateDir:STATE,operationId
  });
  if(result.safeToReplay!==false)deny();
  return result;
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  try{
    const result=await reconcileOneProtectedUpdateFixedRoot();
    process.stdout.write(JSON.stringify(result)+'\n');
  }catch{
    process.stderr.write('protected_root_reconcile_denied_or_unknown\n');
    process.exitCode=1;
  }
}
