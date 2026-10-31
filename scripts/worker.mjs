import { DatabaseSync } from 'node:sqlite';
import { spawnSync } from 'node:child_process';
import { mkdirSync, chmodSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { homedir } from 'node:os';

export const SESSION = 'mcp-dev-hub-14';
export const ALLOWED = Object.freeze({
  'synthetic-one': ['node', '-e', 'console.log("synthetic task one")'],
  'synthetic-two': ['node', '-e', 'console.log("synthetic task two")'],
  'repo-check': ['npm', 'run', 'check']
});
const tmux = (args) => spawnSync('tmux', args, {encoding:'utf8',stdio:['ignore','pipe','pipe']});
const stateDir = () => process.env.MCP_DEV_HUB_STATE_DIR || join(homedir(), '.local','state','mcp-dev-hub');
export function openDb() {
  const dir=resolve(stateDir()); mkdirSync(dir,{recursive:true,mode:0o700}); chmodSync(dir,0o700);
  const db=new DatabaseSync(join(dir,'worker.sqlite'));
  db.exec('CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY, kind TEXT NOT NULL, project TEXT NOT NULL, target TEXT NOT NULL, workspace TEXT NOT NULL, state TEXT NOT NULL, window TEXT, exit_code INTEGER, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)');
  return db;
}
const now=()=>new Date().toISOString();
export function addJob(db,{id,kind,project,target,workspace}) {
  if(!/^[a-z0-9][a-z0-9_-]{2,63}$/.test(id) || !Object.hasOwn(ALLOWED,kind)) throw Error('invalid job');
  if(![project,target,workspace].every(x=>typeof x==='string'&&/^[a-z0-9][a-z0-9_-]{1,63}$/.test(x))) throw Error('invalid authorization scope');
  const scope=process.env.MCP_DEV_HUB_APPROVED_SCOPE;
  if(!scope || scope!==[project,target,workspace].join(':')) throw Error('unapproved scope');
  db.prepare('INSERT INTO jobs(id,kind,project,target,workspace,state,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)').run(id,kind,project,target,workspace,'queued',now(),now());
}
export function jobs(db){return db.prepare('SELECT * FROM jobs ORDER BY created_at,id').all();}
export function ensureSession() {
  if(tmux(['has-session','-t','='+SESSION]).status===0)return;
  if(tmux(['new-session','-d','-s',SESSION,'-n','observer']).status!==0)throw Error('tmux unavailable');
}
function readPane(window) {
  const r=tmux(['capture-pane','-p','-S','-200','-t','='+SESSION+':'+window]);
  return r.status===0?r.stdout:null;
}
function windowAlive(window) {
  const r=tmux(['list-windows','-t','='+SESSION,'-F','#{window_name}']);
  return r.status===0 && r.stdout.split('\n').includes(window);
}
export function reconcile(db) {
  for(const job of jobs(db).filter(j=>j.state==='running')) {
    const pane=readPane(job.window);
    const match=pane?.match(new RegExp('END '+job.id+' exit=([0-9]+)'));
    if(match) {
      const code=Number(match[1]);
      db.prepare('UPDATE jobs SET state=?,exit_code=?,updated_at=? WHERE id=?').run(code===0?'succeeded':'failed',code,now(),job.id);
    } else if(!windowAlive(job.window)) {
      db.prepare('UPDATE jobs SET state=?,updated_at=? WHERE id=?').run('unknown',now(),job.id);
    }
  }
}
export function tick(db) {
  ensureSession();reconcile(db);
  if(jobs(db).some(j=>j.state==='running'||j.state==='unknown'||j.state==='failed'||j.state==='blocked'))return false;
  const job=db.prepare("SELECT * FROM jobs WHERE state='queued' ORDER BY created_at,id LIMIT 1").get();
  if(!job)return false;
  if(process.env.MCP_DEV_HUB_APPROVED_SCOPE!==[job.project,job.target,job.workspace].join(':')){
    db.prepare('UPDATE jobs SET state=?,updated_at=? WHERE id=?').run('blocked',now(),job.id);return false;
  }
  const win='job-'+job.id;
  // The command is selected exclusively from the fixed allowlist; no user-supplied shell text.
  const cmd=ALLOWED[job.kind].map(s=>"'"+s.replaceAll("'","'\\''")+"'").join(' ');
  const script='source "$HOME/.nvm/nvm.sh" 2>/dev/null || true; printf "RUN '+job.id+'\\n"; '+cmd+'; rc=$?; printf "END '+job.id+' exit=%s\\n" "$rc"; exec bash';
  db.prepare('UPDATE jobs SET state=?,window=?,updated_at=? WHERE id=?').run('running',win,now(),job.id);
  const r=tmux(['new-window','-d','-t','='+SESSION,'-c',process.cwd(),'-n',win,'bash','-lc',script]);
  if(r.status!==0)db.prepare('UPDATE jobs SET state=?,updated_at=? WHERE id=?').run('unknown',now(),job.id);
  return r.status===0;
}
export async function runWorker(db,{interval=300}={}) {
  while(true){tick(db);await new Promise(r=>setTimeout(r,interval));}
}
if(process.argv[1]&&import.meta.url===new URL('file://'+resolve(process.argv[1])).href){
  const db=openDb();const action=process.argv[2];
  if(action==='enqueue') {
    const [id,kind,project,target,workspace]=process.argv.slice(3);
    addJob(db,{id,kind,project,target,workspace});console.log('queued',id);
  } else if(action==='status'){reconcile(db);console.log(JSON.stringify(jobs(db),null,2));}
  else if(action==='once'){tick(db);console.log(JSON.stringify(jobs(db),null,2));}
  else if(action==='run'){await runWorker(db);}
  else throw Error('usage: enqueue <id> <allowlisted-kind> <project> <target> <workspace> | status | once | run');
}
