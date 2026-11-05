import { DatabaseSync } from 'node:sqlite';
import {canaryAuthorized} from '../src/jobs/ai-github-canary-policy.mjs';
import {claimDevelopment} from '../src/jobs/ai-development-claims.mjs';
import {randomBytes} from 'node:crypto';
import {trackPr,recordPrGate,prNextAction} from '../src/jobs/pr-automation.mjs';
import {pollPrGithub} from '../src/jobs/pr-github-poll.mjs';
import {pollPrWithGh} from '../src/jobs/pr-gh-cli.mjs';
import { decideReviewRetry } from '../src/jobs/review-retry.mjs';
import { dispatchScheduledCiRetry } from '../src/jobs/ci-retry-dispatch.mjs';
import { ensureCiRetryTable } from '../src/jobs/ci-retry-store.mjs';
import { allocateWorktree } from '../src/jobs/worktree-allocate.mjs';
import { cleanupWorktree, ensureWorktreeTable } from '../src/jobs/worktree-cleanup.mjs';
import { spawnSync,spawn } from 'node:child_process';
import { mkdirSync, chmodSync, readFileSync, rmSync, lstatSync, realpathSync } from 'node:fs';
import { join, resolve, isAbsolute, sep, dirname } from 'node:path';
import { homedir } from 'node:os';
import { pathToFileURL } from 'node:url';

const configuredSession = process.env.MCP_DEV_HUB_TMUX_SESSION || 'mcp-dev-hub-14';
if(!/^[a-z][a-z0-9-]{2,63}$/.test(configuredSession))throw Error('invalid tmux session');
export const SESSION = configuredSession;
// #10 is read-only dashboard/observability. The untrusted PR checkout
// may not launch AI development code until a separately reviewed OS sandbox exists.
// AI_WRITE/AI_PUSH flags alone do NOT make that execution safe.
export function canStartAiDevelopment(){return false;}
export const ALLOWED = Object.freeze({
  'synthetic-one': ['node', '-e', 'console.log("synthetic task one")'],
  'synthetic-two': ['node', '-e', 'console.log("synthetic task two")'],
  'ai-github-canary': ['/usr/bin/node', '/usr/local/lib/mcp-dev-hub/ai-github-canary.mjs'],
  'repo-check': ['npm', 'run', 'check'],
  'cli-smoke': ['node', 'scripts/cli-smoke.mjs'],
  'review-opencode': ['node', '__trusted_runner_required__'],
  'ai-development': ['node', 'scripts/ai-development-run.mjs']
});
const tmux = (args) => spawnSync('tmux', args, {encoding:'utf8',stdio:['ignore','pipe','pipe']});
function immutableTrustedPath(path){
 // The Worker is never run as root. A same-identity writable directory can
 // replace the launcher/bwrap binary even when group/other writes are disabled.
 if(typeof process.getuid!=='function'||process.getuid()===0)return false;
 let current=path;
 try{
  while(true){
   const st=lstatSync(current);
   if(st.isSymbolicLink()||st.uid!==0||(st.mode&0o022)!==0)return false;
   if(current==='/')return true;
   current=dirname(current);
  }
 }catch{return false;}
}
// Only an installed, immutable root-owned controller AND its policy module
// can hold Worker GitHub write authority. No checkout-relative source permitted.
export function trustedCanaryRunner(){
 const root='/usr/local/lib/mcp-dev-hub';
 const files=[join(root,'ai-github-canary.mjs'),join(root,'ai-github-canary-policy.mjs')];
 try{
  const dir=lstatSync(root);
  if(!dir.isDirectory()||!immutableTrustedPath(root))return null;
  for(const file of files){
   const st=lstatSync(file);
   if(!st.isFile()||st.isSymbolicLink()||!immutableTrustedPath(file))return null;
  }
  const node='/usr/bin/node',bwrap='/usr/bin/bwrap',gh='/usr/bin/gh',
    codex=join(root,'codex'),agy=join(root,'agy');
  if(!immutableTrustedPath(node)||!immutableTrustedPath(bwrap)||
     !immutableTrustedPath(gh)||!lstatSync(gh).isFile()||
     !immutableTrustedPath(agy)||!lstatSync(agy).isFile()||
     !immutableTrustedPath(codex)||!lstatSync(codex).isFile())return null;
  return files[0];
 }catch{return null;}
}
// Fail closed unless the trusted reviewer launcher was deployed outside any
// checkout or PR-controlled worktree, with non-symlink regular files.
export function trustedReviewRunner({executionDir,baseSha}={}){
 const root=process.env.MCP_DEV_HUB_TRUSTED_RUNNER_ROOT;
 const bwrap=process.env.MCP_DEV_HUB_BWRAP_BIN;
 if(typeof root!=='string'||!isAbsolute(root)||typeof bwrap!=='string'||
    !isAbsolute(bwrap)||!/^[a-f0-9]{40}$/.test(baseSha||''))return null;
 try{
  const normalized=resolve(root),review=realpathSync(executionDir);
  const repo=realpathSync(process.env.MCP_DEV_HUB_WORKTREE_REPO||process.cwd());
  const worktrees=realpathSync(process.env.MCP_DEV_HUB_WORKTREE_ROOT||process.cwd());
  const blocked=[review,repo,worktrees,realpathSync(process.cwd())];
  if(normalized!==root||realpathSync(root)!==root||
    blocked.some(path=>root===path||root.startsWith(path+sep)||path.startsWith(root+sep)))return null;
  const dir=lstatSync(root),file=join(root,'review-opencode.mjs'),st=lstatSync(file);
  if(!dir.isDirectory()||dir.isSymbolicLink()||(dir.mode&0o022)!==0||
    !st.isFile()||st.isSymbolicLink()||(st.mode&0o022)!==0||realpathSync(file)!==file)return null;
  const bw=lstatSync(bwrap);
  if(!bw.isFile()||bw.isSymbolicLink()||(bw.mode&0o022)!==0||realpathSync(bwrap)!==bwrap)return null;
  if(!immutableTrustedPath(root)||!immutableTrustedPath(file)||!immutableTrustedPath(bwrap))return null;
  return file;
 }catch{return null;}
}

export function publicEvents(db, project) {
  if (project !== undefined && !/^[a-z0-9][a-z0-9_-]{1,63}$/.test(project)) throw Error('invalid project');
  return jobs(db).filter(job => project === undefined || job.project === project).map(({id,kind,project,state,exit_code,created_at,updated_at})=>({
    id,kind,project,state,exitCode:exit_code,createdAt:created_at,updatedAt:updated_at
  }));
}
// Immutable, monotonic database event IDs survive process restarts and job state updates.
export function eventHistory(db,project,since=0,limit=100) {
  if(typeof project!=='string'|| !/^[a-z0-9][a-z0-9_-]{1,63}$/.test(project))throw Error('invalid project');
  if(!Number.isSafeInteger(since)||since<0||!Number.isSafeInteger(limit)||limit<1||limit>200)throw Error('invalid cursor');
  return db.prepare('SELECT id,job_id AS jobId,kind,project,state,exit_code AS exitCode,created_at AS at FROM job_events WHERE project=? AND id>? ORDER BY id LIMIT ?').all(project,since,limit);
}
export function eventBounds(db,project){
  if(typeof project!=='string'|| !/^[a-z0-9][a-z0-9_-]{1,63}$/.test(project))throw Error('invalid project');
  return db.prepare('SELECT MIN(id) AS first, MAX(id) AS last FROM job_events WHERE project=?').get(project);
}
const stateDir = () => process.env.MCP_DEV_HUB_STATE_DIR || join(homedir(), '.local','state','mcp-dev-hub');
export function openDb({readOnly=false}={}) {
  const dir=resolve(stateDir());
  if(!readOnly){mkdirSync(dir,{recursive:true,mode:0o700}); chmodSync(dir,0o700);}
  const db=new DatabaseSync(join(dir,'worker.sqlite'),{readOnly,timeout:5000});
  if(readOnly)return db;
  db.exec(`CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY, kind TEXT NOT NULL, project TEXT NOT NULL, target TEXT NOT NULL, workspace TEXT NOT NULL, state TEXT NOT NULL, window TEXT, exit_code INTEGER, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS review_attempts (job_id TEXT PRIMARY KEY REFERENCES jobs(id), attempt INTEGER NOT NULL DEFAULT 1 CHECK(attempt BETWEEN 1 AND 4), retry_at TEXT, last_reason TEXT, updated_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS review_results (job_id TEXT PRIMARY KEY REFERENCES jobs(id), status TEXT NOT NULL, summary TEXT NOT NULL, recorded_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS review_result_history (job_id TEXT NOT NULL,attempt INTEGER NOT NULL,status TEXT NOT NULL,summary TEXT NOT NULL,recorded_at TEXT NOT NULL,PRIMARY KEY(job_id,attempt));
    CREATE TABLE IF NOT EXISTS job_run_nonces (job_id TEXT PRIMARY KEY,attempt INTEGER NOT NULL,nonce TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS review_attempt_log (job_id TEXT NOT NULL, attempt INTEGER NOT NULL, reason TEXT NOT NULL, recorded_at TEXT NOT NULL, PRIMARY KEY(job_id,attempt));
    CREATE TABLE IF NOT EXISTS job_events (id INTEGER PRIMARY KEY AUTOINCREMENT,job_id TEXT NOT NULL, kind TEXT NOT NULL, project TEXT NOT NULL, state TEXT NOT NULL, exit_code INTEGER, created_at TEXT NOT NULL);
    CREATE INDEX IF NOT EXISTS idx_job_events_project_id ON job_events(project,id);
    CREATE TRIGGER IF NOT EXISTS job_event_insert AFTER INSERT ON jobs BEGIN
      INSERT INTO job_events(job_id,kind,project,state,exit_code,created_at) VALUES(NEW.id,NEW.kind,NEW.project,NEW.state,NEW.exit_code,NEW.updated_at);
    END;
    CREATE TRIGGER IF NOT EXISTS job_event_state AFTER UPDATE OF state,exit_code ON jobs
    WHEN NEW.state IS NOT OLD.state OR NEW.exit_code IS NOT OLD.exit_code BEGIN
      INSERT INTO job_events(job_id,kind,project,state,exit_code,created_at) VALUES(NEW.id,NEW.kind,NEW.project,NEW.state,NEW.exit_code,NEW.updated_at);
    END;`);
  // One-time snapshot for jobs created by older Worker versions; never double backfill.
  db.exec(`CREATE TABLE IF NOT EXISTS worker_schema_meta (key TEXT PRIMARY KEY,value TEXT NOT NULL)`);
  db.exec('BEGIN IMMEDIATE');
  try {
    const migrated=db.prepare("SELECT value FROM worker_schema_meta WHERE key='event_backfill_v1'").get();
    if(!migrated){
      db.exec('INSERT INTO job_events(job_id,kind,project,state,exit_code,created_at) SELECT j.id,j.kind,j.project,j.state,j.exit_code,j.updated_at FROM jobs j WHERE NOT EXISTS (SELECT 1 FROM job_events e WHERE e.job_id=j.id)');
      db.prepare("INSERT INTO worker_schema_meta(key,value) VALUES('event_backfill_v1','done')").run();
    }
    db.exec('COMMIT');
  }catch(e){db.exec('ROLLBACK');throw e;}
  return db;
}
const now=()=>new Date().toISOString();
export function addJob(db,{id,kind,project,target,workspace}) {
  if(!/^[a-z0-9][a-z0-9_-]{2,63}$/.test(id) || !Object.hasOwn(ALLOWED,kind)) throw Error('invalid job');
  if(![project,target,workspace].every(x=>typeof x==='string'&&/^[a-z0-9][a-z0-9_-]{1,63}$/.test(x)) || target!=='local') throw Error('invalid authorization scope');
  const scope=process.env.MCP_DEV_HUB_APPROVED_SCOPE;
  if(!scope || scope!==[project,target,workspace].join(':')) throw Error('unapproved scope');
  db.prepare('INSERT INTO jobs(id,kind,project,target,workspace,state,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)').run(id,kind,project,target,workspace,'queued',now(),now());
}
export function registerReviewJob(db,job) {
  if(job.kind !== 'review-opencode') throw Error('review execution adapter not approved');
  addJob(db,job);
  db.prepare('INSERT INTO review_attempts(job_id,attempt,updated_at) VALUES(?,1,?)').run(job.id,now());
}
export function recordReviewFailure(db,id,reason,{outcomeKnown=true,processAlive=false,at=Date.now()}={}) {
  if(!Number.isFinite(at)) throw Error('invalid time');
  const job=db.prepare('SELECT j.state,j.project,j.target,j.workspace,r.attempt FROM jobs j JOIN review_attempts r ON j.id=r.job_id WHERE j.id=?').get(id);
  if(!job)throw Error('unknown review job');
  if(job.state!=='failed')return {state:job.state,retry:false};
  const decision=decideReviewRetry({attempt:job.attempt,reason,outcomeKnown,processAlive});
  db.exec('BEGIN IMMEDIATE');
  try {
    const current=db.prepare('SELECT attempt FROM review_attempts WHERE job_id=?').get(id);
    const state=db.prepare('SELECT state FROM jobs WHERE id=?').get(id);
    if(current.attempt!==job.attempt || state.state!=='failed'){db.exec('ROLLBACK');return {state:state.state,retry:false};}
    db.prepare('INSERT OR IGNORE INTO review_attempt_log(job_id,attempt,reason,recorded_at) VALUES(?,?,?,?)').run(id,job.attempt,reason,new Date(at).toISOString());
    const nextState=decision.retry?'retry_scheduled':decision.state;
    db.prepare('UPDATE review_attempts SET attempt=?,retry_at=?,last_reason=?,updated_at=? WHERE job_id=?').run(decision.retry?decision.nextAttempt:job.attempt,decision.retry?new Date(at+decision.delayMs).toISOString():null,reason,new Date(at).toISOString(),id);
    db.prepare('UPDATE jobs SET state=?,updated_at=? WHERE id=?').run(nextState,new Date(at).toISOString(),id);
    db.exec('COMMIT');return {...decision,state:nextState};
  }catch(e){db.exec('ROLLBACK');throw e;}
}
export function autoScheduleReviewFailures(db,{at=Date.now()}={}) {
  const failures=db.prepare("SELECT j.id,j.exit_code FROM jobs j JOIN review_attempts r ON j.id=r.job_id WHERE j.state='failed'").all();
  let handled=0;
  for(const failure of failures){
    const reason=failure.exit_code===124?'timeout':failure.exit_code===75?'service_unavailable':null;
    if(reason){recordReviewFailure(db,failure.id,reason,{at});handled++;}
  }
  return handled;
}
export function releaseDueReviewRetries(db,{at=Date.now()}={}) {
  const approved=process.env.MCP_DEV_HUB_APPROVED_SCOPE;
  const rows=db.prepare("SELECT j.id,j.project,j.target,j.workspace FROM jobs j JOIN review_attempts r ON j.id=r.job_id WHERE j.state='retry_scheduled' AND r.retry_at <= ? ORDER BY r.retry_at").all(new Date(at).toISOString());
  let released=0;
  for(const row of rows){
    if(approved!==[row.project,row.target,row.workspace].join(':'))continue;
    released+=db.prepare("UPDATE jobs SET state='queued',exit_code=NULL,window=NULL,updated_at=? WHERE id=? AND state='retry_scheduled'").run(new Date(at).toISOString(),row.id).changes;
  }
  return released;
}
export function jobs(db){return db.prepare('SELECT * FROM jobs ORDER BY created_at,id').all();}
export function ensureSession() {
  if(tmux(['has-session','-t','='+SESSION]).status===0)return;
  // Concurrent observers can create the session after our first check.
  // Only accept an unsuccessful create when the exact session now exists.
  if(tmux(['new-session','-d','-s',SESSION,'-n','observer']).status!==0 &&
     tmux(['has-session','-t','='+SESSION]).status!==0)throw Error('tmux unavailable');
}
function readPane(window) {
  const r=tmux(['capture-pane','-p','-S','-','-t','='+SESSION+':'+window]);
  return r.status===0?r.stdout:null;
}
function windowAlive(window) {
  const r=tmux(['list-windows','-t','='+SESSION,'-F','#{window_name}']);
  return r.status===0 && r.stdout.split('\n').includes(window);
}
export function collectReviewResult(db,id) {
  if(!/^[a-z0-9][a-z0-9_-]{2,63}$/.test(id)) throw Error('invalid job id');
  const job=db.prepare('SELECT kind,state FROM jobs WHERE id=?').get(id);
  if(!job || job.kind!=='review-opencode') throw Error('not a review job');
  const attempt=db.prepare('SELECT attempt FROM review_attempts WHERE job_id=?').get(id)?.attempt;
  if(!attempt)return false;
  const path=join(resolve(stateDir()),'review-results',id+'-attempt-'+attempt+'.json');
  let result;
  try { result=JSON.parse(readFileSync(path,'utf8')); } catch { return false; }
  if(result.jobId!==id || result.attempt!==attempt || !['completed','failed','timed_out'].includes(result.status) ||
      typeof result.summary!=='string' || result.summary.length>12000) return false;
  db.prepare('INSERT OR IGNORE INTO review_result_history(job_id,attempt,status,summary,recorded_at) VALUES(?,?,?,?,?)').run(id,attempt,result.status,result.summary,new Date().toISOString());
  db.prepare('INSERT INTO review_results(job_id,status,summary,recorded_at) VALUES(?,?,?,?) ON CONFLICT(job_id) DO UPDATE SET status=excluded.status,summary=excluded.summary,recorded_at=excluded.recorded_at')
    .run(id,result.status,result.summary,new Date().toISOString());
  return result.status==='completed';
}
export function reconcile(db) {
  for(const job of jobs(db).filter(j=>j.state==='running'||
       (j.kind==='ai-github-canary'&&j.state==='starting'))) {
    const pane=job.kind==='ai-github-canary'?null:readPane(job.window);
    const attempt=db.prepare('SELECT attempt FROM review_attempts WHERE job_id=?').get(job.id)?.attempt??1;
    const nonce=db.prepare('SELECT nonce FROM job_run_nonces WHERE job_id=? AND attempt=?').get(job.id,attempt)?.nonce;
    // Durable nonce-bound completion proof, independent of tmux pane wrapping.
    let exitLine=null;
    try { exitLine=readFileSync(join(resolve(stateDir()),'run-proofs',job.id+'-attempt-'+attempt+'.txt'),'utf8').trim(); } catch {}
    const match=nonce && exitLine?.startsWith('END '+job.id+' attempt='+attempt+' proof='+nonce+' exit=');
    if(match && exitLine) {
      const rawCode=exitLine.slice(exitLine.lastIndexOf('=')+1);
      if(!/^(0|[1-9][0-9]{0,2})$/.test(rawCode)||Number(rawCode)>255)continue;
      const code=Number(rawCode);
      const reviewCollected=job.kind==='review-opencode' ? collectReviewResult(db,job.id) : true;
      const validReview=job.kind!=='review-opencode' || (code===0 && reviewCollected);
      const terminal=job.kind==='ai-github-canary'&&code===76?'unknown':
        code===0&&validReview?'succeeded':'failed';
      db.prepare("UPDATE jobs SET state=?,exit_code=?,updated_at=? WHERE id=? AND state IN ('starting','running')")
        .run(terminal,code===0&&!validReview?75:code,now(),job.id);
      // Persist terminal result before attempting pane retirement for every job.
      if(job.kind!=='ai-github-canary'&&
         db.prepare('SELECT state FROM jobs WHERE id=?').get(job.id)?.state!=='running')
        tmux(['kill-window','-t','='+SESSION+':'+job.window]);
    } else if(job.kind==='ai-github-canary'){
      // No tmux dependency. A missing proof becomes UNKNOWN after a bounded
      // deadline, never an automatic retry or a fabricated success.
      if(Date.now()-Date.parse(job.updated_at)>900000)
       db.prepare("UPDATE jobs SET state=?,updated_at=? WHERE id=? AND state IN ('starting','running')").run('unknown',now(),job.id);
    } else if(!windowAlive(job.window)) {
      db.prepare("UPDATE jobs SET state=?,updated_at=? WHERE id=? AND state='running'").run('unknown',now(),job.id);
    }
  }
}
export function quarantineUnknownJob(db,{id,confirmedNoLiveProcess=false,evidenceId}){
 if(!/^[a-z0-9][a-z0-9_-]{2,63}$/.test(id)||
    !confirmedNoLiveProcess||!/^verified-[a-z0-9_-]{4,90}$/.test(evidenceId||''))
  throw Error('operator reconciliation evidence required');
 const row=db.prepare('SELECT state,window FROM jobs WHERE id=?').get(id);
 if(!row||row.state!=='unknown')return false;
 if(row.window&&windowAlive(row.window))throw Error('live window still exists');
 return db.prepare("UPDATE jobs SET state='blocked',updated_at=? WHERE id=? AND state='unknown'")
  .run(now(),id).changes===1;
}
export function retireTerminalWindows(db){
 let retired=0;
 for(const job of jobs(db).filter(j=>['succeeded','failed','blocked'].includes(j.state)&&j.window)){
  if(job.kind==='ai-github-canary')continue;
  if(!windowAlive(job.window))continue;
  const r=tmux(['kill-window','-t','='+SESSION+':'+job.window]);
  if(r.status===0)retired++;
 }
 return retired;
}
export function reconcileManagedWorktrees(db) {
  const root=process.env.MCP_DEV_HUB_WORKTREE_ROOT;
  if(!root)return 0;
  ensureWorktreeTable(db);
  let processed=0;
  for(const row of db.prepare("SELECT w.task_id,j.state,j.window FROM managed_worktrees w JOIN jobs j ON j.id=w.task_id WHERE w.state='active'").all()) {
    if(!['succeeded','failed','blocked'].includes(row.state))continue;
    const alive=Boolean(row.window && windowAlive(row.window));
    const preserved=row.state==='succeeded' && (db.prepare('SELECT 1 FROM review_results WHERE job_id=?').get(row.task_id)!==undefined || db.prepare("SELECT kind FROM jobs WHERE id=?").get(row.task_id)?.kind!=='review-opencode');
    const outcome=cleanupWorktree(db,{taskId:row.task_id,root,repoDir:process.env.MCP_DEV_HUB_WORKTREE_REPO||root,taskTerminal:true,leaseAlive:alive,resultsPreserved:preserved});
    if(outcome.removed)processed++;
  }
  return processed;
}
export function reconcileStarting(db,{at=Date.now()}={}) {
  for(const job of jobs(db).filter(j=>j.state==='starting')){
    if(job.kind==='ai-github-canary')continue; // reconcile() checks this controller's durable proof.
    if(windowAlive(job.window))
      db.prepare("UPDATE jobs SET state='running',updated_at=? WHERE id=? AND state='starting'").run(new Date(at).toISOString(),job.id);
    else if(at-Date.parse(job.updated_at)>30000)
      db.prepare("UPDATE jobs SET state='unknown',updated_at=? WHERE id=? AND state='starting'").run(new Date(at).toISOString(),job.id);
  }
}
export function tick(db) {
  ensureSession();reconcileStarting(db);reconcile(db);retireTerminalWindows(db);autoScheduleReviewFailures(db);releaseDueReviewRetries(db);
  reconcileManagedWorktrees(db);
  if(jobs(db).some(j=>j.state==='starting'||j.state==='running'||j.state==='unknown'))return false;
  const job=db.prepare("SELECT * FROM jobs WHERE state='queued' ORDER BY created_at,id LIMIT 1").get();
  if(!job)return false;
  // PR checkout code must never run via npm, CLI smoke or AI development
  // without independently verified OS isolation. No flag can bypass this gate.
  if(['ai-development','repo-check','cli-smoke'].includes(job.kind)&&!canStartAiDevelopment()){
    db.prepare("UPDATE jobs SET state='blocked',updated_at=? WHERE id=? AND state='queued'").run(now(),job.id);
    return false; // Never spawn checkout-controlled code before OS isolation exists.
  }
  if(job.kind==='ai-github-canary' && !canaryAuthorized({
    job,scope:process.env.MCP_DEV_HUB_APPROVED_SCOPE,
    write:process.env.MCP_DEV_HUB_ENABLE_AI_WRITE,
    push:process.env.MCP_DEV_HUB_ENABLE_AI_PUSH,
    enabled:process.env.MCP_DEV_HUB_ENABLE_GH_CANARY,
    approvedId:process.env.MCP_DEV_HUB_CANARY_APPROVED_JOB_ID
  })){
    db.prepare("UPDATE jobs SET state='blocked',updated_at=? WHERE id=? AND state='queued'").run(now(),job.id);
    return false;
  }
  if(job.target!=='local' || process.env.MCP_DEV_HUB_APPROVED_SCOPE!==[job.project,job.target,job.workspace].join(':')){
    db.prepare('UPDATE jobs SET state=?,updated_at=? WHERE id=?').run('blocked',now(),job.id);return false;
  }
  const attempt=db.prepare('SELECT attempt FROM review_attempts WHERE job_id=?').get(job.id)?.attempt??1;
  const win='job-'+job.id+'-a'+attempt;
  let executionDir=process.cwd();
  const pinnedPrJob=job.id.startsWith('review-pr-')||job.id.startsWith('fix-pr-');
  const trackedSha=pinnedPrJob
    ? db.prepare('SELECT head_sha FROM pr_automation WHERE pr_key=?').get(process.env.MCP_DEV_HUB_AUTOMATION_PR_KEY||'')?.head_sha : null;
  const baseSha=trackedSha && (job.id==='review-pr-'+trackedSha.slice(0,12)||job.id==='fix-pr-'+trackedSha.slice(0,12))
    ? trackedSha : (pinnedPrJob ? null : process.env.MCP_DEV_HUB_WORKTREE_BASE_SHA);
  if(pinnedPrJob&&(!baseSha||!process.env.MCP_DEV_HUB_WORKTREE_ROOT||!process.env.MCP_DEV_HUB_WORKTREE_REPO)){
    db.prepare("UPDATE jobs SET state='blocked',updated_at=? WHERE id=? AND state='queued'").run(now(),job.id);
    return false;
  }
  if(job.kind!=='ai-github-canary' && process.env.MCP_DEV_HUB_WORKTREE_ROOT && process.env.MCP_DEV_HUB_WORKTREE_REPO && baseSha){
    try {
      const existing=db.prepare("SELECT path FROM managed_worktrees WHERE task_id=?").get(job.id);
      if(existing)executionDir=existing.path;
      else executionDir=allocateWorktree(db,{taskId:job.id,root:process.env.MCP_DEV_HUB_WORKTREE_ROOT,repoDir:process.env.MCP_DEV_HUB_WORKTREE_REPO,baseSha,branch:'task/'+job.id}).path;
    }catch(e){db.prepare("UPDATE jobs SET state='blocked',updated_at=? WHERE id=? AND state='queued'").run(now(),job.id);return false;}
  }
  // Results of earlier attempts remain immutable; a new attempt uses a different result file.
  // The command is selected exclusively from the fixed allowlist; no user-supplied shell text.
  const trustedRunner=job.kind==='review-opencode'?trustedReviewRunner({executionDir,baseSha}):null;
  if(job.kind==='review-opencode'&&!trustedRunner){
   db.prepare("UPDATE jobs SET state='blocked',updated_at=? WHERE id=? AND state='queued'").run(now(),job.id);
   return false;
  }
  const canaryRunner=job.kind==='ai-github-canary'?trustedCanaryRunner():null;
  if(job.kind==='ai-github-canary'&&!canaryRunner){
    db.prepare("UPDATE jobs SET state='blocked',updated_at=? WHERE id=? AND state='queued'").run(now(),job.id);
    return false;
  }
  const argv=canaryRunner?['/usr/bin/node',canaryRunner]:
    trustedRunner?['node',trustedRunner]:ALLOWED[job.kind];
  const cmd=argv.map(s=>"'"+s.replaceAll("'","'\\''")+"'").join(' ');
  const quoteShell=(s)=>"'" + String(s).replaceAll("'","'\\''") + "'";
  const reviewEnv=job.kind==='review-opencode' ? 'MCP_DEV_HUB_REVIEW_JOB_ID='+quoteShell(job.id)+' MCP_DEV_HUB_REVIEW_ATTEMPT='+quoteShell(attempt)+' MCP_DEV_HUB_REVIEW_RESULT_DIR='+quoteShell(join(stateDir(),'review-results'))+
    ' MCP_DEV_HUB_REVIEW_SOURCE_DIR='+quoteShell(executionDir)+
    ' MCP_DEV_HUB_REVIEW_HEAD_SHA='+quoteShell(baseSha)+
    ' MCP_DEV_HUB_BWRAP_BIN='+quoteShell(process.env.MCP_DEV_HUB_BWRAP_BIN)+' ' : '';
  const aiSettings=job.kind==='ai-development'?{
    MCP_DEV_HUB_AI_JOB_ID:job.id,
    MCP_DEV_HUB_AI_HEAD_SHA:baseSha,
    MCP_DEV_HUB_AI_WORKTREE:executionDir,
    MCP_DEV_HUB_AI_BRANCH:'task/'+job.id,
    MCP_DEV_HUB_ENABLE_AI_WRITE:process.env.MCP_DEV_HUB_ENABLE_AI_WRITE==='1'?'1':'0',
    MCP_DEV_HUB_ENABLE_AI_PUSH:process.env.MCP_DEV_HUB_ENABLE_AI_PUSH==='1'?'1':'0',
    MCP_DEV_HUB_WORKTREE_REPO:process.env.MCP_DEV_HUB_WORKTREE_REPO||'',
    MCP_DEV_HUB_WORKTREE_ROOT:process.env.MCP_DEV_HUB_WORKTREE_ROOT||'',
    MCP_DEV_HUB_STATE_DIR:stateDir(),
    MCP_DEV_HUB_AGY_BIN:process.env.MCP_DEV_HUB_AGY_BIN||'agy',
    MCP_DEV_HUB_CODEX_BIN:process.env.MCP_DEV_HUB_CODEX_BIN||'codex'
  }:null;
  const devEnv=aiSettings?Object.entries(aiSettings).map(([key,value])=>key+'='+quoteShell(value)).join(' ')+' ':'';
  const canarySettings=job.kind==='ai-github-canary'?{
    MCP_DEV_HUB_CANARY_JOB_ID:job.id,
    MCP_DEV_HUB_STATE_DIR:stateDir(),
    MCP_DEV_HUB_APPROVED_SCOPE:process.env.MCP_DEV_HUB_APPROVED_SCOPE,
    MCP_DEV_HUB_ENABLE_GH_CANARY:process.env.MCP_DEV_HUB_ENABLE_GH_CANARY,
    MCP_DEV_HUB_CANARY_APPROVED_JOB_ID:process.env.MCP_DEV_HUB_CANARY_APPROVED_JOB_ID,
    MCP_DEV_HUB_ENABLE_AI_WRITE:process.env.MCP_DEV_HUB_ENABLE_AI_WRITE,
    MCP_DEV_HUB_ENABLE_AI_PUSH:process.env.MCP_DEV_HUB_ENABLE_AI_PUSH
  }:null;
  const nonce=randomBytes(16).toString('hex');
  const proofDir=join(stateDir(),'run-proofs');
  mkdirSync(proofDir,{recursive:true,mode:0o700});
  const proofFile=join(proofDir,job.id+'-attempt-'+attempt+'.txt');
  // The canary never uses tmux, a login shell, startup files or env wrappers.
  // A direct Node child inherits ONLY explicit, reviewed environment fields.
  if(canarySettings){
   const claimed=db.prepare('UPDATE jobs SET state=?,window=?,updated_at=? WHERE id=? AND state=?')
    .run('starting','canary-'+job.id,now(),job.id,'queued');
   if(claimed.changes!==1)return false;
   db.prepare('INSERT INTO job_run_nonces(job_id,attempt,nonce) VALUES(?,?,?) ON CONFLICT(job_id) DO UPDATE SET attempt=excluded.attempt,nonce=excluded.nonce')
    .run(job.id,attempt,nonce);
   let child;
   try{
    child=spawn('/usr/bin/node',[canaryRunner],{
     cwd:'/',detached:true,stdio:'ignore',
     env:{HOME:homedir(),PATH:'/usr/bin:/bin',LANG:'C.UTF-8',
      ...Object.fromEntries(Object.entries(canarySettings).map(([k,v])=>[k,v||''])),
      MCP_DEV_HUB_CANARY_NONCE:nonce,
      MCP_DEV_HUB_CANARY_ATTEMPT:String(attempt),
      MCP_DEV_HUB_CANARY_PROOF_FILE:proofFile}
    });
   }catch{
    db.prepare("UPDATE jobs SET state='unknown',updated_at=? WHERE id=? AND state='starting'").run(now(),job.id);
    return false;
   }
   child.on('error',()=>{try{
    db.prepare("UPDATE jobs SET state='unknown',updated_at=? WHERE id=? AND state IN ('starting','running')").run(now(),job.id);
   }catch{}});
   if(!Number.isInteger(child.pid)||child.pid<2){
    db.prepare("UPDATE jobs SET state='unknown',updated_at=? WHERE id=? AND state='starting'").run(now(),job.id);
    return false;
   }
   child.unref();
   db.prepare("UPDATE jobs SET state='running',updated_at=? WHERE id=? AND state='starting'").run(now(),job.id);
   return true;
  }
  const proofTail='; rc=$?; printf "END '+job.id+' attempt='+attempt+' proof='+nonce+' exit=%s\n" "$rc" > '+quoteShell(proofFile)+'.tmp; mv '+quoteShell(proofFile)+'.tmp '+quoteShell(proofFile);
  const script='source "$HOME/.nvm/nvm.sh" 2>/dev/null || true; printf "RUN '+job.id+'\n"; '+reviewEnv+devEnv+cmd+proofTail+'; exec bash';
  const claimed=db.prepare('UPDATE jobs SET state=?,window=?,updated_at=? WHERE id=? AND state=?').run('starting',win,now(),job.id,'queued');
  if(claimed.changes!==1)return false;
  db.prepare('INSERT INTO job_run_nonces(job_id,attempt,nonce) VALUES(?,?,?) ON CONFLICT(job_id) DO UPDATE SET attempt=excluded.attempt,nonce=excluded.nonce').run(job.id,attempt,nonce);
  const r=tmux(['new-window','-d','-t','='+SESSION,'-c',executionDir,'-n',win,'bash','-lc',script]);
  if(r.status!==0)db.prepare("UPDATE jobs SET state='unknown',updated_at=? WHERE id=? AND state='starting'").run(now(),job.id);
  else db.prepare("UPDATE jobs SET state='running',updated_at=? WHERE id=? AND state='starting'").run(now(),job.id);
  return r.status===0;
}
export async function dispatchDueCiRetries(db,{at=Date.now(),dispatch=dispatchScheduledCiRetry}={}) {
  const repo=process.env.MCP_DEV_HUB_GITHUB_REPOSITORY;
  const token=process.env.MCP_DEV_HUB_GITHUB_TOKEN;
  // Fail closed unless both the exact repository and an Actions-write token are configured.
  if(!repo || !token)return 0;
  ensureCiRetryTable(db);
  const due=db.prepare("SELECT run_id FROM ci_retry_runs WHERE state='retry_scheduled' AND retry_at<=? ORDER BY retry_at LIMIT 10").all(new Date(at).toISOString());
  let attempted=0;
  for(const row of due){
    await dispatch(db,{runId:row.run_id,repo,token,now:at});
    attempted++;
  }
  return attempted;
}
export function enqueuePrReviewIfReady(db,result){
 if(result?.gate!=='independent_review'||!['verifying','blocked'].includes(result?.state)||!result.headSha)return false;
 // Require a separately approved local execution scope and an exact pinned checkout.
 if(!process.env.MCP_DEV_HUB_WORKTREE_ROOT||!process.env.MCP_DEV_HUB_WORKTREE_REPO)return false;
 if(!/^[0-9a-f]{40}$/.test(result.headSha))return false;
 const prKey=process.env.MCP_DEV_HUB_AUTOMATION_PR_KEY;
 if(!prKey||db.prepare('SELECT head_sha FROM pr_automation WHERE pr_key=?').get(prKey)?.head_sha!==result.headSha)return false;
 const scope=process.env.MCP_DEV_HUB_APPROVED_SCOPE?.split(':');
 if(!scope||scope.length!==3||scope[1]!=='local')return false;
 const id='review-pr-'+result.headSha.slice(0,12);
 if(db.prepare('SELECT 1 FROM jobs WHERE id=?').get(id))return false;
 registerReviewJob(db,{id,kind:'review-opencode',project:scope[0],target:scope[1],workspace:scope[2]});
 return true;
}
export function reconcilePrReviewEvidence(db,{prKey=process.env.MCP_DEV_HUB_AUTOMATION_PR_KEY}={}){
 if(!prKey)return {state:'unconfigured'};
 const pr=db.prepare('SELECT head_sha FROM pr_automation WHERE pr_key=?').get(prKey);
 if(!pr)return {state:'untracked'};
 const id='review-pr-'+pr.head_sha.slice(0,12);
 const job=db.prepare('SELECT state FROM jobs WHERE id=?').get(id);
 if(!job)return {state:'not_queued'};
 if(job.state==='succeeded'){
   const review=db.prepare('SELECT status,summary FROM review_results WHERE job_id=?').get(id);
   // A completed AI report is not independent approval. Require a separately
   // authenticated review verdict before the independent_review gate can pass.
   const hasFindings=review?.status==='completed' && /REVIEW_FINDINGS:\s*(?:[1-9][.)]|[-*]\s+)(?!no\s+findings)/i.test(review.summary);
   return {state:hasFindings?'remediation_required':review?.status==='completed'?'awaiting_independent_approval':'review_unverified',jobId:id};
 }
 return {state:job.state,jobId:id};
}
export function claimPrDevelopmentIfNeeded(db,{prKey=process.env.MCP_DEV_HUB_AUTOMATION_PR_KEY}={}){
 if(!prKey)return {state:'unconfigured'};
 const pr=db.prepare('SELECT head_sha FROM pr_automation WHERE pr_key=?').get(prKey);
 if(!pr)return {state:'untracked'};
 const review=reconcilePrReviewEvidence(db,{prKey});
 if(review.state!=='remediation_required')return {state:review.state,claimed:false};
 // This records a single pending task only; it MUST NOT execute edits or push
 // code without distinct validated task authorization and independent review.
 const jobId='fix-pr-'+pr.head_sha.slice(0,12);
 const result=claimDevelopment(db,{jobId,headSha:pr.head_sha});
 if((result.claimed||result.phase==='claimed') && process.env.MCP_DEV_HUB_ENABLE_AI_WRITE==='1' && !db.prepare('SELECT 1 FROM jobs WHERE id=?').get(jobId)){
  const scope=process.env.MCP_DEV_HUB_APPROVED_SCOPE?.split(':');
  if(scope?.length===3&&scope[1]==='local'&&process.env.MCP_DEV_HUB_WORKTREE_ROOT&&process.env.MCP_DEV_HUB_WORKTREE_REPO)
   addJob(db,{id:jobId,kind:'ai-development',project:scope[0],target:scope[1],workspace:scope[2]});
 }
 return {state:'remediation_required',claimed:result.claimed,jobId};
}
export async function runWorker(db,{interval=300}={}) {
 let lastPrPoll=0;
 while(true){
    tick(db);
    try{await dispatchDueCiRetries(db);}catch{console.error('CI_RETRY_DISPATCH_ERROR');}
    const prKey=process.env.MCP_DEV_HUB_AUTOMATION_PR_KEY;
    const token=process.env.MCP_DEV_HUB_GITHUB_TOKEN;
    if(prKey&&Date.now()-lastPrPoll>=30000){
      lastPrPoll=Date.now();
      try{enqueuePrReviewIfReady(db,token?await pollPrGithub({db,prKey,token}):await pollPrWithGh({db,prKey}));claimPrDevelopmentIfNeeded(db,{prKey});}
      catch{console.error('PR_POLL_UNAVAILABLE_OR_BLOCKED');}
    }
    await new Promise(r=>setTimeout(r,interval));
  }
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href){
  const db=openDb();const action=process.argv[2];
  if(action==='enqueue') {
    const [id,kind,project,target,workspace]=process.argv.slice(3);
    const job={id,kind,project,target,workspace};
    if(kind==='review-opencode')registerReviewJob(db,job);
    else addJob(db,job);
    console.log('queued',id);
  } else if(action==='pr-poll'){
    const prKey=process.argv[3];
    const token=process.env.MCP_DEV_HUB_GITHUB_TOKEN;
    const result=token?await pollPrGithub({db,prKey,token}):await pollPrWithGh({db,prKey});
    const reviewQueued=enqueuePrReviewIfReady(db,result);
    console.log(JSON.stringify({...result,reviewQueued}));
  } else if(action==='pr-track'){
    const [prKey,headSha]=process.argv.slice(3);
    console.log(JSON.stringify(trackPr(db,{prKey,headSha})));
  } else if(action==='pr-gate'){
    const [prKey,headSha,gate,verdict,evidenceId]=process.argv.slice(3);
    recordPrGate(db,{prKey,headSha,gate,verdict,evidenceId});
    console.log(JSON.stringify(prNextAction(db,{prKey,observedSha:headSha})));
  } else if(action==='pr-next'){
    const [prKey,observedSha]=process.argv.slice(3);
    console.log(JSON.stringify(prNextAction(db,{prKey,observedSha})));
  } else if(action==='status'){reconcile(db);console.log(JSON.stringify(jobs(db),null,2));}
  else if(action==='once'){tick(db);console.log(JSON.stringify(jobs(db),null,2));}
  else if(action==='events'){reconcile(db);console.log(JSON.stringify(publicEvents(db)));}
  else if(action==='run'){await runWorker(db);}
  else throw Error('usage: enqueue <id> <allowlisted-kind> <project> <target> <workspace> | status | once | run');
}
