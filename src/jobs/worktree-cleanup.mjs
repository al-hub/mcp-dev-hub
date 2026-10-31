import {spawnSync} from 'node:child_process';
import {realpathSync} from 'node:fs';
import {resolve,relative,isAbsolute,sep} from 'node:path';
const validId=/^[a-z0-9][a-z0-9_-]{2,63}$/;
const git=(args,cwd)=>spawnSync('git',args,{cwd,encoding:'utf8',shell:false});
function within(root,path){
 const rel=relative(root,path);
 return rel!=='' && rel!=='..' && !rel.startsWith('..'+sep) && !isAbsolute(rel);
}
// Only registered worktrees created under the approved root can be retired.
export function ensureWorktreeTable(db){
 db.exec(`CREATE TABLE IF NOT EXISTS managed_worktrees(
  task_id TEXT PRIMARY KEY,path TEXT NOT NULL UNIQUE,branch TEXT NOT NULL,
  state TEXT NOT NULL,updated_at TEXT NOT NULL
 )`);
}
export function registerWorktree(db,{taskId,path,branch,root}){
 if(!validId.test(taskId)||!branch||!root)throw Error('invalid worktree registry');
 const base=realpathSync(root),target=resolve(path);
 if(!within(base,target))throw Error('worktree outside approved root');
 ensureWorktreeTable(db);
 db.prepare("INSERT INTO managed_worktrees(task_id,path,branch,state,updated_at) VALUES(?,?,?,'active',?)")
   .run(taskId,target,branch,new Date().toISOString());
}
export function cleanupWorktree(db,{taskId,root,taskTerminal=false,leaseAlive=true,resultsPreserved=false,gitRunner=git}){
 ensureWorktreeTable(db);
 const row=db.prepare('SELECT * FROM managed_worktrees WHERE task_id=?').get(taskId);
 if(!row)return {state:'not_registered',removed:false};
 if(row.state==='removed')return {state:'removed',removed:false};
 if(!taskTerminal||leaseAlive||!resultsPreserved)return {state:'retained',removed:false};
 let base,target;
 try{
  base=realpathSync(root);target=realpathSync(row.path);
  if(!within(base,target))throw Error('outside root');
  const listed=gitRunner(['worktree','list','--porcelain'],base);
  if(listed.status!==0||!listed.stdout.split('\n').includes('worktree '+target))throw Error('unverified worktree');
  const status=gitRunner(['status','--porcelain','--untracked-files=all'],target);
  if(status.status!==0||status.stdout.trim())throw Error('dirty worktree');
  const removed=gitRunner(['worktree','remove',target],base);
  if(removed.status!==0)throw Error('git refused removal');
  db.prepare("UPDATE managed_worktrees SET state='removed',updated_at=? WHERE task_id=?")
    .run(new Date().toISOString(),taskId);
  return {state:'removed',removed:true};
 }catch{
  db.prepare("UPDATE managed_worktrees SET state='recovery_required',updated_at=? WHERE task_id=?")
    .run(new Date().toISOString(),taskId);
  return {state:'recovery_required',removed:false};
 }
}
