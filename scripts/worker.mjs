import { DatabaseSync } from 'node:sqlite';
import {randomBytes} from 'node:crypto';
import {trackPr,recordPrGate,prNextAction} from '../src/jobs/pr-automation.mjs';
import {pollPrGithub} from '../src/jobs/pr-github-poll.mjs';
import {pollPrWithGh} from '../src/jobs/pr-gh-cli.mjs';
import { decideReviewRetry } from '../src/jobs/review-retry.mjs';
import { dispatchScheduledCiRetry } from '../src/jobs/ci-retry-dispatch.mjs';
import { ensureCiRetryTable } from '../src/jobs/ci-retry-store.mjs';
import { allocateWorktree } from '../src/jobs/worktree-allocate.mjs';
import { cleanupWorktree, ensureWorktreeTable } from '../src/jobs/worktree-cleanup.mjs';
import { spawnSync } from 'node:child_process';
import { mkdirSync, chmodSync, readFileSync, rmSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { homedir } from 'node:os';
import { pathToFileURL } from 'node:url';

const configuredSession = process.env.MCP_DEV_HUB_TMUX_SESSION || 'mcp-dev-hub-14';
if(!/^[a-z][a-z0-9-]{2,63}$/.test(configuredSession))throw Error('invalid tmux session');
export const SESSION = configuredSession;
export const ALLOWED = Object.freeze({
  'synthetic-one': ['node', '-e', 'console.log("synthetic task one")'],
  'synthetic-two': ['node', '-e', 'console.log("synthetic task two")'],
  'repo-check': ['npm', 'run', 'check'],
  'cli-smoke': ['node', 'scripts/cli-smoke.mjs'],
  'review-opencode': ['node', 'scripts/review-opencode.mjs']
});
const tmux = (args) => spawnSync('tmux', args, {encoding:'utf8',stdio:['ignore','pipe','pipe']});
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
  if(tmux(['new-session','-d','-s',SESSION,'-n','observer']).status!==0)throw Error('tmux unavailable');
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
  for(const job of jobs(db).filter(j=>j.state==='running')) {
    const pane=readPane(job.window);
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
      db.prepare("UPDATE jobs SET state=?,exit_code=?,updated_at=? WHERE id=? AND state='running'").run(code===0 && validReview?'succeeded':'failed',code===0 && !validReview?75:code,now(),job.id);
      // Persist terminal result before attempting pane retirement for every job.
      if(db.prepare('SELECT state FROM jobs WHERE id=?').get(job.id)?.state!=='running')
        tmux(['kill-window','-t','='+SESSION+':'+job.window]);
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
  if(job.target!=='local' || process.env.MCP_DEV_HUB_APPROVED_SCOPE!==[job.project,job.target,job.workspace].join(':')){
    db.prepare('UPDATE jobs SET state=?,updated_at=? WHERE id=?').run('blocked',now(),job.id);return false;
  }
  const attempt=db.prepare('SELECT attempt FROM review_attempts WHERE job_id=?').get(job.id)?.attempt??1;
  const win='job-'+job.id+'-a'+attempt;
  let executionDir=process.cwd();
  const trackedSha=job.id.startsWith('review-pr-')
    ? db.prepare('SELECT head_sha FROM pr_automation WHERE pr_key=?').get(process.env.MCP_DEV_HUB_AUTOMATION_PR_KEY||'')?.head_sha : null;
  const baseSha=trackedSha && job.id==='review-pr-'+trackedSha.slice(0,12)
    ? trackedSha : (job.id.startsWith('review-pr-') ? null : process.env.MCP_DEV_HUB_WORKTREE_BASE_SHA);
  if(job.id.startsWith('review-pr-')&&(!baseSha||!process.env.MCP_DEV_HUB_WORKTREE_ROOT||!process.env.MCP_DEV_HUB_WORKTREE_REPO)){
    db.prepare("UPDATE jobs SET state='blocked',updated_at=? WHERE id=? AND state='queued'").run(now(),job.id);
    return false;
  }
  if(process.env.MCP_DEV_HUB_WORKTREE_ROOT && process.env.MCP_DEV_HUB_WORKTREE_REPO && baseSha){
    try {
      const existing=db.prepare("SELECT path FROM managed_worktrees WHERE task_id=?").get(job.id);
      if(existing)executionDir=existing.path;
      else executionDir=allocateWorktree(db,{taskId:job.id,root:process.env.MCP_DEV_HUB_WORKTREE_ROOT,repoDir:process.env.MCP_DEV_HUB_WORKTREE_REPO,baseSha,branch:'task/'+job.id}).path;
    }catch(e){db.prepare("UPDATE jobs SET state='blocked',updated_at=? WHERE id=? AND state='queued'").run(now(),job.id);return false;}
  }
  // Results of earlier attempts remain immutable; a new attempt uses a different result file.
  // The command is selected exclusively from the fixed allowlist; no user-supplied shell text.
  const cmd=ALLOWED[job.kind].map(s=>"'"+s.replaceAll("'","'\\''")+"'").join(' ');
  const quoteShell=(s)=>"'" + String(s).replaceAll("'","'\\''") + "'";
  const reviewEnv=job.kind==='review-opencode' ? 'MCP_DEV_HUB_REVIEW_JOB_ID='+quoteShell(job.id)+' MCP_DEV_HUB_REVIEW_ATTEMPT='+quoteShell(attempt)+' MCP_DEV_HUB_REVIEW_RESULT_DIR='+quoteShell(join(stateDir(),'review-results'))+' ' : '';
  const nonce=randomBytes(16).toString('hex');
  const proofDir=join(stateDir(),'run-proofs');
  mkdirSync(proofDir,{recursive:true,mode:0o700});
  const proofFile=join(proofDir,job.id+'-attempt-'+attempt+'.txt');
  const script='source "$HOME/.nvm/nvm.sh" 2>/dev/null || true; printf "RUN '+job.id+'\\n"; '+reviewEnv+cmd+'; rc=$?; printf "END '+job.id+' attempt='+attempt+' proof='+nonce+' exit=%s\\n" "$rc" > '+quoteShell(proofFile)+'.tmp; mv '+quoteShell(proofFile)+'.tmp '+quoteShell(proofFile)+'; exec bash';
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
export async function runWorker(db,{interval=300}={}) {
 let lastPrPoll=0;
 while(true){
    tick(db);
    try{await dispatchDueCiRetries(db);}catch{console.error('CI_RETRY_DISPATCH_ERROR');}
    const prKey=process.env.MCP_DEV_HUB_AUTOMATION_PR_KEY;
    const token=process.env.MCP_DEV_HUB_GITHUB_TOKEN;
    if(prKey&&Date.now()-lastPrPoll>=30000){
      lastPrPoll=Date.now();
      try{enqueuePrReviewIfReady(db,token?await pollPrGithub({db,prKey,token}):await pollPrWithGh({db,prKey}));reconcilePrReviewEvidence(db,{prKey});}
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
