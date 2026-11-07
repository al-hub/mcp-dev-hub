// #35: read-only, fail-closed recovery classification for a protected update.
// NOT an updater, replay command, root entrypoint, permission grant, or a
// replacement for the independently authenticated root supervisor.
// The root supervisor must pin root/stateDir and original baseline outside
// Issue text, the Worker checkout, and all untrusted request parameters.
import {readStoredProtectedUpdateJournal}
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

/** Inspect one already-stored operation without writing any journal, pointer,
 * file or service. This is an information-only classification.
 *
 * A matching pointer is NOT permission to retry, roll back or mark health
 * verified: the signed issuer, protected journal and OS service observer are
 * separate mandatory production trust gates.
 */
export function reconcileProtectedUpdateCandidate({
  root,stateDir,operationId
}={}){
  if(typeof operationId!=='string'||!ID.test(operationId)||
     typeof root!=='string'||typeof stateDir!=='string')deny();
  const j=readStoredProtectedUpdateJournal(stateDir,operationId);
  if(j===null)return Object.freeze({
    operationId,state:'absent',observed:'unverified',
    safeToReplay:false,requiresReconciliation:true
  });
  // Previous commit comes only from the root-held, durably parsed v2 journal,
  // NEVER from a Worker/Issue/recovery call parameter.
  if(j.head===j.previousCommit||
     !COMPLETED.has(j.phase)&&!UNCERTAIN.has(j.phase))deny();

  // The pointer must reference one of the two signed, journalled versions.
  // Unexpected paths, corrupt contents or additional files fail closed.
  const snap=inspectProtectedCurrentSnapshot(root);
  let observed;
  if(snap.commit===j.previousCommit&&
     exactHashes(j.oldHashes,snap.files))observed='previous';
  else if(snap.commit===j.head&&
          exactHashes(j.newHashes,snap.files))observed='next';
  else deny();

  if(j.phase==='verified'&&observed!=='next')deny();
  if((j.phase==='rolled_back'||j.phase==='aborted')&&
     observed!=='previous')deny();

  return Object.freeze({
    operationId,state:COMPLETED.has(j.phase)?j.phase:'unknown',
    observed,recordedPhase:j.phase,sequence:j.sequence,
    safeToReplay:false,
    requiresReconciliation:!COMPLETED.has(j.phase)
  });
}
