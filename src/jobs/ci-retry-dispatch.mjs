import {claimDueCiRetry,markCiRetryOutcome} from './ci-retry-store.mjs';

// Dispatches only an already classified and durably scheduled retry.
// Token must have Actions write permission. Never retry an uncertain response.
export async function dispatchScheduledCiRetry(db,{runId,repo,token,now=Date.now(),fetchImpl=fetch}){
 if(!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repo) ||
    !Number.isSafeInteger(runId)||runId<=0 || typeof token!=='string'||!token)
   throw Error('CI retry credentials or scope invalid');
 if(!claimDueCiRetry(db,{runId,now}))return {dispatched:false,state:'not_due_or_claimed'};
 const url='https://api.github.com/repos/'+repo+'/actions/runs/'+runId+'/rerun-failed-jobs';
 try{
   const response=await fetchImpl(url,{
     method:'POST',
     headers:{Accept:'application/vnd.github+json',Authorization:'Bearer '+token,
              'X-GitHub-Api-Version':'2022-11-28'},
     signal:AbortSignal.timeout(15000)
   });
   const acknowledged=response.status===201;
   markCiRetryOutcome(db,{runId,acknowledged});
   return {dispatched:acknowledged,state:acknowledged?'reconciling':'unknown',httpStatus:response.status};
 }catch{
   markCiRetryOutcome(db,{runId,acknowledged:false});
   return {dispatched:false,state:'unknown'};
 }
}
