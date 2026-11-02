import {spawnSync} from 'node:child_process';
import {realpathSync,lstatSync} from 'node:fs';
import {resolve,join,relative,isAbsolute,sep} from 'node:path';
import {ensureWorktreeTable,registerWorktree} from './worktree-cleanup.mjs';
const valid=/^[a-z0-9][a-z0-9_-]{2,63}$/;
const defaultGit=(args,cwd)=>spawnSync('git',args,{cwd,encoding:'utf8',shell:false});
function occupied(path){try{lstatSync(path);return true;}catch(e){if(e.code==='ENOENT')return false;throw e;}}
function inside(root,target){const r=relative(root,target);return r!==''&&r!=='..'&&!r.startsWith('..'+sep)&&!isAbsolute(r);}
export function allocateWorktree(db,{taskId,root,repoDir,baseSha,branch,gitRunner=defaultGit}){
 if(!valid.test(taskId)|| !/^[0-9a-f]{40}$/.test(baseSha)||!/^task\/[a-z0-9_-]{3,64}$/.test(branch))throw Error('invalid allocation');
 const base=realpathSync(root),repo=realpathSync(repoDir),target=resolve(join(base,'job-'+taskId));
 if(!inside(base,target)||occupied(target))throw Error('target already exists or outside root');
 ensureWorktreeTable(db);
 const prior=db.prepare('SELECT task_id,state FROM managed_worktrees WHERE task_id=? OR path=?').get(taskId,target);
 if(prior)throw Error('worktree already registered');
 // Persist the intent before invoking git, so interrupted or failed setup is discoverable.
 registerWorktree(db,{taskId,path:target,branch,root:base,state:'allocating'});
 try {
  const result=gitRunner(['worktree','add','-b',branch,target,baseSha],repo);
  if(result.status!==0)throw Error('worktree create failed');
  let actual;
  try{actual=realpathSync(target);}catch{throw Error('worktree path unresolved');}
  if(actual!==target||!inside(base,actual))throw Error('worktree path changed');
  db.prepare("UPDATE managed_worktrees SET state='active',updated_at=? WHERE task_id=? AND state='allocating'")
    .run(new Date().toISOString(),taskId);
 }catch(e){
  // Do not guess whether git created a partial tree: preserve a durable recovery record.
  db.prepare("UPDATE managed_worktrees SET state='recovery_required',updated_at=? WHERE task_id=? AND state='allocating'")
    .run(new Date().toISOString(),taskId);
  throw Error('worktree allocation uncertain; manual reconciliation required',{cause:e});
 }
 return {taskId,path:target,baseSha,state:'active'};
}
export function listManagedWorktrees(db){
 ensureWorktreeTable(db);
 return db.prepare('SELECT task_id AS taskId,path,state,updated_at AS updatedAt FROM managed_worktrees ORDER BY task_id').all();
}
