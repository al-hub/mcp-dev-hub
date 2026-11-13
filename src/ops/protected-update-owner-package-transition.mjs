// #35 source-only readback classification for a staged package replacement.
// No filesystem, process, GitHub, signing, or privileged operations. Callers
// must independently verify all observations. No result authorizes any action.
const SHA=/^[a-f0-9]{40}$/;
const HASH=/^[a-f0-9]{64}$/;
const matches=(pattern,x)=>typeof x==='string'&&pattern.test(x);
const exact=(o,keys)=>o!==null&&typeof o==='object'&&!Array.isArray(o)&&
  Object.keys(o).length===keys.length&&keys.every(k=>Object.hasOwn(o,k));
const tupleKeys=['head','packDigest','base','prNumber','ciRunId'];
const packageKeys=['head','packDigest'];
const positive=x=>Number.isSafeInteger(x)&&x>0;
const isPackage=p=>exact(p,packageKeys)&&matches(SHA,p.head)&&
  matches(HASH,p.packDigest);
const isTuple=t=>exact(t,tupleKeys)&&matches(SHA,t.head)&&
  matches(HASH,t.packDigest)&&matches(SHA,t.base)&&t.base!==t.head&&
  positive(t.prNumber)&&positive(t.ciRunId);
const samePackage=(a,b)=>a.head===b.head&&a.packDigest===b.packDigest;
const sameTuple=(a,b)=>tupleKeys.every(k=>a[k]===b[k]);
const result=state=>Object.freeze({state,sourceReadbackOnly:true,
  requiresReconciliation:state==='unknown',safeToReplay:false,
  installAuthorized:false,rollbackAuthorized:false});

/** null is verified absence. An omitted/undefined observation is unknown.
 * "candidate_consistent" means only that the supplied package and trust
 * tuple agree and an exact original package/tuple backup is observed.
 */
export function classifyOwnerPackageTransition(evidence){
 const keys=['previous','candidate','activePackage','activeTrust',
   'backupPackage','backupTrust','pending'];
 if(!exact(evidence,keys))return result('unknown');
 const {previous,candidate,activePackage,activeTrust,backupPackage,
   backupTrust,pending}=evidence;
 if(!isTuple(previous)||!isTuple(candidate)||
    previous.head===candidate.head||previous.packDigest===candidate.packDigest||
    previous.ciRunId===candidate.ciRunId||previous.prNumber!==candidate.prNumber||
    !isPackage(activePackage)||!isTuple(activeTrust)||pending!==false)
   return result('unknown');
 const backupAbsent=backupPackage===null&&backupTrust===null;
 const originalPreserved=isPackage(backupPackage)&&isTuple(backupTrust)&&
   samePackage(backupPackage,previous)&&sameTuple(backupTrust,previous);
 if(samePackage(activePackage,previous)&&sameTuple(activeTrust,previous)&&
    (backupAbsent||originalPreserved))return result('original_consistent');
 if(samePackage(activePackage,candidate)&&sameTuple(activeTrust,candidate)&&
    originalPreserved)return result('candidate_consistent');
 return result('unknown');
}
