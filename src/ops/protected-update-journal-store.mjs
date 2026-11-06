// #35 Gate B: non-privileged, fail-closed journal persistence foundation.
// NOT an installer, signer, trust-root verifier or permission grant.
// The future fixed root-owned updater MUST independently authenticate stateDir,
// its ancestors, provenance, operation policy and source file bytes.
import {
  constants, closeSync, fstatSync, fsyncSync, lstatSync, openSync,
  readFileSync, readdirSync, realpathSync, renameSync, unlinkSync,
  writeFileSync
} from 'node:fs';
import {isAbsolute, join, resolve} from 'node:path';
import {
  startProtectedUpdateJournal, advanceProtectedUpdateJournal,
  parseProtectedUpdateJournal
} from './protected-update-journal.mjs';

const ID=/^[a-f0-9]{32}$/;
const FILE=/^([a-f0-9]{32})\.json$/;
const TERMINAL=new Set(['verified','rolled_back','aborted']);
const fail=()=>{throw Error('protected_journal_store_guard_failed');};
const readFlags=constants.O_RDONLY|constants.O_NOFOLLOW;
const writeFlags=constants.O_WRONLY|constants.O_CREAT|
  constants.O_EXCL|constants.O_NOFOLLOW;

function checkedDir(stateDir) {
  if(typeof stateDir!=='string'||!isAbsolute(stateDir)||
      resolve(stateDir)!==stateDir)fail();
  const st=lstatSync(stateDir);
  if(!st.isDirectory()||st.isSymbolicLink()||
      (st.mode&0o077)!==0||realpathSync(stateDir)!==stateDir)fail();
  return st.uid;
}
function syncDir(stateDir) {
  const fd=openSync(stateDir,constants.O_RDONLY|constants.O_DIRECTORY|
    constants.O_NOFOLLOW);
  try {if(!fstatSync(fd).isDirectory())fail();fsyncSync(fd);}
  finally {closeSync(fd);}
}
function filename(stateDir,operationId) {
  if(typeof operationId!=='string'||!ID.test(operationId))fail();
  return join(stateDir,operationId+'.json');
}
function listJournalIds(stateDir) {
  const names=readdirSync(stateDir);
  if(names.length>129)fail();
  const ids=[];
  for(const name of names) {
    if(name==='.lock')continue;
    const m=FILE.exec(name);
    // Leftover stage files and unknown entries are uncertain: fail closed.
    if(!m)fail();
    ids.push(m[1]);
  }
  return ids;
}
function withLock(stateDir,fn) {
  checkedDir(stateDir);
  let fd;
  try {
    // O_EXCL ensures a crash-stale lock is never silently stolen.
    fd=openSync(join(stateDir,'.lock'),writeFlags,0o600);
  } catch {fail();}
  try {
    fsyncSync(fd);
    syncDir(stateDir);
    return fn();
  } finally {
    closeSync(fd);
    // Only the holder that created this lock may release it.
    unlinkSync(join(stateDir,'.lock'));
    syncDir(stateDir);
  }
}
export function readStoredProtectedUpdateJournal(stateDir,operationId) {
  const owner=checkedDir(stateDir);
  const path=filename(stateDir,operationId);
  let fd;
  try {fd=openSync(path,readFlags);} catch(e) {
    if(e.code==='ENOENT')return null;
    throw e;
  }
  try {
    const st=fstatSync(fd);
    if(!st.isFile()||st.uid!==owner||(st.mode&0o077)!==0||
        st.size<1||st.size>4096)fail();
    return parseProtectedUpdateJournal(readFileSync(fd,{encoding:'utf8'}));
  } finally {closeSync(fd);}
}
function atomicWrite(stateDir,operationId,journal) {
  const target=filename(stateDir,operationId);
  // A deterministic, exclusive stage name preserves crash evidence.
  // A leftover stage must be investigated, not automatically deleted.
  const staged=join(stateDir,operationId+'.tmp');
  const fd=openSync(staged,writeFlags,0o600);
  try {
    writeFileSync(fd,JSON.stringify(journal),'utf8');
    fsyncSync(fd);
  } finally {closeSync(fd);}
  renameSync(staged,target);
  syncDir(stateDir);
}
export function beginStoredProtectedUpdateJournal(stateDir,args) {
  return withLock(stateDir,()=>{
    const j=startProtectedUpdateJournal(args);
    const ids=listJournalIds(stateDir);
    if(ids.length>=128||ids.includes(j.operationId))fail();
    // Never begin another revision over an unresolved or unknown update.
    for(const id of ids) {
      const prior=readStoredProtectedUpdateJournal(stateDir,id);
      if(!prior||!TERMINAL.has(prior.phase))fail();
    }
    atomicWrite(stateDir,j.operationId,j);
    return j;
  });
}
export function advanceStoredProtectedUpdateJournal(
  stateDir,operationId,transition
) {
  return withLock(stateDir,()=>{
    // No side effects beyond the journal. Caller must persist switch_pending
    // BEFORE any protected OS action and externally verify actual hashes.
    const previous=readStoredProtectedUpdateJournal(stateDir,operationId);
    if(!previous)fail();
    const next=advanceProtectedUpdateJournal(previous,{
      ...transition,operationId
    });
    atomicWrite(stateDir,operationId,next);
    return next;
  });
}
