// #35: inert durable updater journal transition checks. NO privileged effects.
// The root-owned caller must fsync/atomic-persist BEFORE each external effect,
// lock updates, obtain trusted file hashes, and reconcile unknown outcomes.
// This module never updates a file, grants sudo, starts services or runs code.
const SHA = /^[a-f0-9]{40}$/;
const HASH = /^[a-f0-9]{64}$/;
const OP = /^[a-f0-9]{32}$/;
export const PROTECTED_PAIR = Object.freeze([
  'ai-github-canary-policy.mjs', 'ai-github-canary.mjs'
]);
const FIELDS = Object.freeze([
  'version','operationId','head','base','oldHashes','newHashes',
  'phase','sequence','createdAtMs','updatedAtMs'
]);
const MOVES = Object.freeze({
  prepared: ['switch_pending','aborted'],
  switch_pending: ['switched','rolled_back','unknown'],
  switched: ['verified','rollback_pending','unknown'],
  rollback_pending: ['rolled_back','unknown'],
  rolled_back: [], verified: [], aborted: [], unknown: []
});
const deny = () => {throw Error('invalid_protected_update_journal');};
const exact = (value,fields) => value !== null &&
  typeof value==='object' && !Array.isArray(value) &&
  Object.keys(value).length===fields.length &&
  fields.every(field=>Object.hasOwn(value,field));
const validHashes = h => exact(h,PROTECTED_PAIR) &&
  PROTECTED_PAIR.every(name=>typeof h[name]==='string' && HASH.test(h[name]));
const cloneHashes = h=>Object.freeze(Object.fromEntries(
  PROTECTED_PAIR.map(name=>[name,h[name]])
));
function validate(j) {
  if(!exact(j,FIELDS) || j.version!==1 || !OP.test(j.operationId||'') ||
     !SHA.test(j.head||'') || !SHA.test(j.base||'') || j.head===j.base ||
     !validHashes(j.oldHashes) || !validHashes(j.newHashes) ||
     !Object.hasOwn(MOVES,j.phase) ||
     !Number.isSafeInteger(j.sequence) || j.sequence<0 ||
     !Number.isSafeInteger(j.createdAtMs) ||
     !Number.isSafeInteger(j.updatedAtMs) ||
     j.createdAtMs<1 || j.updatedAtMs<j.createdAtMs) deny();
  return j;
}
export function startProtectedUpdateJournal({
  operationId,head,base,oldHashes,newHashes,nowMs
}={}) {
  const j={version:1,operationId,head,base,oldHashes,newHashes,
    phase:'prepared',sequence:0,createdAtMs:nowMs,updatedAtMs:nowMs};
  validate(j);
  // A no-op update is not evidence of two genuine revisions.
  if(PROTECTED_PAIR.every(n=>oldHashes[n]===newHashes[n]))deny();
  return Object.freeze({...j,oldHashes:cloneHashes(oldHashes),
    newHashes:cloneHashes(newHashes)});
}
export function advanceProtectedUpdateJournal(j,{
  operationId,expectedSequence,to,nowMs,observedHashes,serviceHealthVerified=false
}={}) {
  validate(j);
  if(operationId!==j.operationId ||
     !Number.isSafeInteger(expectedSequence) ||
     expectedSequence!==j.sequence ||
     !MOVES[j.phase].includes(to) ||
     !Number.isSafeInteger(nowMs) || nowMs<j.updatedAtMs) deny();
  if(['switched','rolled_back','verified'].includes(to)){
    // An observation must be supplied by a separately trusted root caller,
    // never an Issue or a model. Equality is NOT physical proof by itself.
    const expected=to==='rolled_back'?j.oldHashes:j.newHashes;
    if(!validHashes(observedHashes) ||
       PROTECTED_PAIR.some(n=>observedHashes[n]!==expected[n]))deny();
  } else if(observedHashes!==undefined) deny();
  if(to==='verified' && serviceHealthVerified!==true)deny();
  if(serviceHealthVerified!==false && to!=='verified')deny();
  const next={...j,phase:to,sequence:j.sequence+1,updatedAtMs:nowMs};
  return Object.freeze({...next,
    oldHashes:cloneHashes(j.oldHashes),newHashes:cloneHashes(j.newHashes)});
}

/**
 * Validate a durable readback record before any transition. Exact JSON
 * roundtrip denies duplicate keys, unnormalized numeric fields and ambiguous
 * bytes. Parsing is NOT OS authorization or a replay-clearance mechanism.
 */
export function parseProtectedUpdateJournal(rawJson) {
  if(typeof rawJson!=='string' || Buffer.byteLength(rawJson,'utf8')>4096)
    deny();
  let j;
  try { j=JSON.parse(rawJson); } catch { deny(); }
  if(JSON.stringify(j)!==rawJson) deny();
  validate(j);
  return Object.freeze({...j,oldHashes:cloneHashes(j.oldHashes),
    newHashes:cloneHashes(j.newHashes)});
}
