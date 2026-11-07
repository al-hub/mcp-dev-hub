// #35: read-only, fail-closed recovery classification for a protected update.
// NOT an updater, replay command, root entrypoint, permission grant, or a
// replacement for the independently authenticated root supervisor.
// The root supervisor pins root/stateDir outside untrusted requests.
import {readStoredProtectedUpdateHistory}
  from './protected-update-journal-store.mjs';
import {inspectProtectedCurrentSnapshot}
  from './protected-update-release-pointer.mjs';

const ID=/^[a-f0-9]{32}$/;
const deny=()=>{throw Error('protected_update_reconciliation_denied');};
const COMPLETED=new Set(['verified','rolled_back','aborted']);
const UNCERTAIN=new Set([
  'prepared','switch_pending','switched','rollback_pending','unknown'
]);
function exactHashes(expected,actual){
  if(!expected||!Array.isArray(actual)||actual.length!==2)return false;
  return actual.length===Object.keys(expected).length&&
    actual.every(x=>typeof x.name==='string'&&
      typeof x.sha256==='string'&&expected[x.name]===x.sha256);
}
function observedVersion(snap,commit,hashes){
  return snap.commit===commit&&exactHashes(hashes,snap.files);
}
/** Inspect the requested operation ID plus the bounded durable successor
 * chain. Historical completed results remain queryable after subsequent
 * updates/rollbacks; active or unknown descendants are never promoted.
 * A live/stale journal lock, broken history, invalid current release or
 * pointer/hash mismatch fails closed. NOTHING is written or replayed.
 */
export function reconcileProtectedUpdateCandidate({
  root,stateDir,operationId
}={}){
  if(typeof operationId!=='string'||!ID.test(operationId)||
     typeof root!=='string'||typeof stateDir!=='string')deny();
  const history=readStoredProtectedUpdateHistory(stateDir);
  const j=history.find(row=>row.operationId===operationId);
  if(!j)return Object.freeze({
    operationId,state:'absent',observed:'unverified',
    safeToReplay:false,requiresReconciliation:true
  });
  if(j.head===j.previousCommit||
     !COMPLETED.has(j.phase)&&!UNCERTAIN.has(j.phase))deny();
  // The history reader orders each record, binds its prior commit/hash to
  // the previous terminal record, and rejects a nonterminal predecessor.
  const last=history.at(-1);
  const snap=inspectProtectedCurrentSnapshot(root);
  let latestObserved;
  if(COMPLETED.has(last.phase)){
    const currentCommit=last.phase==='verified'?last.head:
      last.previousCommit;
    const currentHashes=last.phase==='verified'?last.newHashes:
      last.oldHashes;
    if(!observedVersion(snap,currentCommit,currentHashes))deny();
    latestObserved=last.phase==='verified'?'next':'previous';
  }else if(UNCERTAIN.has(last.phase)){
    if(observedVersion(snap,last.previousCommit,last.oldHashes))
      latestObserved='previous';
    else if(observedVersion(snap,last.head,last.newHashes))
      latestObserved='next';
    else deny();
  }else deny();

  const historical=j!==last;
  if(historical&&!COMPLETED.has(j.phase))deny();
  const successorUnknown=!COMPLETED.has(last.phase);
  return Object.freeze({
    operationId,
    state:COMPLETED.has(j.phase)?j.phase:'unknown',
    observed:historical?
      (successorUnknown?'successor_unknown':'superseded'):
      latestObserved,
    recordedPhase:j.phase,sequence:j.sequence,
    safeToReplay:false,
    requiresReconciliation:historical?successorUnknown:
      !COMPLETED.has(j.phase)
  });
}
