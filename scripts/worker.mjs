import { DatabaseSync } from 'node:sqlite';
import { decideReviewRetry } from '../src/jobs/review-retry.mjs';
import { spawnSync } from 'node:child_process';
import { mkdirSync, chmodSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { homedir } from 'node:os';
import { pathToFileURL } from 'node:url';

export const SESSION = 'mcp-dev-hub-14';
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
export function openDb() {
  const dir=resolve(stateDir()); mkdirSync(dir,{recursive:true,mode:0o700}); chmodSync(dir,0o700);
  const db=new DatabaseSync(join(dir,'worker.sqlite'));
  db.exec(`CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY, kind TEXT NOT NULL, project TEXT NOT NULL, target TEXT NOT NULL, workspace TEXT NOT NULL, state TEXT NOT NULL, window TEXT, exit_code INTEGER, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS review_attempts (job_id TEXT PRIMARY KEY REFERENCES jobs(id), attempt INTEGER NOT NULL DEFAULT 1 CHECK(attempt BETWEEN 1 AND 4), retry_at TEXT, last_reason TEXT, updated_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS review_results (job_id TEXT PRIMARY KEY REFERENCES jobs(id), status TEXT NOT NULL, summary TEXT NOT NULL, recorded_at TEXT NOT NULL);
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
  db.exec('INSERT INTO job_events(job_id,kind,project,state,exit_code,created_at) SELECT j.id,j.kind,j.project,j.state,j.exit_code,j.updated_at FROM jobs j WHERE NOT EXISTS (SELECT 1 FROM job_events e WHERE e.job_id=j.id)');
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
  const path=join(resolve(stateDir()),'review-results',id+'.json');
  let result;
  try { result=JSON.parse(readFileSync(path,'utf8')); } catch { return false; }
  if(result.jobId!==id || !['completed','failed','timed_out'].includes(result.status) ||
      typeof result.summary!=='string' || result.summary.length>12000) return false;
  db.prepare('INSERT INTO review_results(job_id,status,summary,recorded_at) VALUES(?,?,?,?) ON CONFLICT(job_id) DO UPDATE SET status=excluded.status,summary=excluded.summary,recorded_at=excluded.recorded_at')
    .run(id,result.status,result.summary,new Date().toISOString());
  return result.status==='completed';
}
export function reconcile(db) {
  for(const job of jobs(db).filter(j=>j.state==='running')) {
    const pane=readPane(job.window);
    const match=pane?.match(new RegExp('END '+job.id+' exit=([0-9]+)'));
    if(match) {
      const code=Number(match[1]);
      const validReview=job.kind!=='review-opencode' || (code===0 && collectReviewResult(db,job.id));
      db.prepare('UPDATE jobs SET state=?,exit_code=?,updated_at=? WHERE id=?').run(code===0 && validReview?'succeeded':'failed',code===0 && !validReview?75:code,now(),job.id);
    } else if(!windowAlive(job.window)) {
      db.prepare('UPDATE jobs SET state=?,updated_at=? WHERE id=?').run('unknown',now(),job.id);
    }
  }
}
export function tick(db) {
  ensureSession();reconcile(db);autoScheduleReviewFailures(db);releaseDueReviewRetries(db);
  if(jobs(db).some(j=>j.state==='running'||j.state==='unknown'||j.state==='failed'||j.state==='blocked'))return false;
  const job=db.prepare("SELECT * FROM jobs WHERE state='queued' ORDER BY created_at,id LIMIT 1").get();
  if(!job)return false;
  if(job.target!=='local' || process.env.MCP_DEV_HUB_APPROVED_SCOPE!==[job.project,job.target,job.workspace].join(':')){
    db.prepare('UPDATE jobs SET state=?,updated_at=? WHERE id=?').run('blocked',now(),job.id);return false;
  }
  const win='job-'+job.id;
  // The command is selected exclusively from the fixed allowlist; no user-supplied shell text.
  const cmd=ALLOWED[job.kind].map(s=>"'"+s.replaceAll("'","'\\''")+"'").join(' ');
  const reviewEnv=job.kind==='review-opencode' ? 'MCP_DEV_HUB_REVIEW_JOB_ID='+job.id+' MCP_DEV_HUB_REVIEW_RESULT_DIR="'+join(stateDir(),'review-results')+'" ' : '';
  const script='source "$HOME/.nvm/nvm.sh" 2>/dev/null || true; printf "RUN '+job.id+'\\n"; '+reviewEnv+cmd+'; rc=$?; printf "END '+job.id+' exit=%s\\n" "$rc"; exec bash';
  const claimed=db.prepare('UPDATE jobs SET state=?,window=?,updated_at=? WHERE id=? AND state=?').run('running',win,now(),job.id,'queued');
  if(claimed.changes!==1)return false;
  const r=tmux(['new-window','-d','-t','='+SESSION,'-c',process.cwd(),'-n',win,'bash','-lc',script]);
  if(r.status!==0)db.prepare('UPDATE jobs SET state=?,updated_at=? WHERE id=?').run('unknown',now(),job.id);
  return r.status===0;
}
export async function runWorker(db,{interval=300}={}) {
  while(true){tick(db);await new Promise(r=>setTimeout(r,interval));}
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href){
  const db=openDb();const action=process.argv[2];
  if(action==='enqueue') {
    const [id,kind,project,target,workspace]=process.argv.slice(3);
    addJob(db,{id,kind,project,target,workspace});console.log('queued',id);
  } else if(action==='status'){reconcile(db);console.log(JSON.stringify(jobs(db),null,2));}
  else if(action==='once'){tick(db);console.log(JSON.stringify(jobs(db),null,2));}
  else if(action==='events'){reconcile(db);console.log(JSON.stringify(publicEvents(db)));}
  else if(action==='run'){await runWorker(db);}
  else throw Error('usage: enqueue <id> <allowlisted-kind> <project> <target> <workspace> | status | once | run');
}
