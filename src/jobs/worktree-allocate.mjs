import {spawnSync} from 'node:child_process';
import {realpathSync,existsSync} from 'node:fs';
import {resolve,join,relative,isAbsolute,sep} from 'node:path';
import {ensureWorktreeTable,registerWorktree} from './worktree-cleanup.mjs';
const valid=/^[a-z0-9][a-z0-9_-]{2,63}$/;
const defaultGit=(args,cwd)=>spawnSync('git',args,{cwd,encoding:'utf8',shell:false});
function inside(root,target){const r=relative(root,target);return r!==''&&r!=='..'&&!r.startsWith('..'+sep)&&!isAbsolute(r);}
export function allocateWorktree(db,{taskId,root,repoDir,baseSha,branch,gitRunner=defaultGit}){
 if(!valid.test(taskId)|| !/^[0-9a-f]{40}$/.test(baseSha)||!/^task\/[a-z0-9_-]{3,64}$/.test(branch))throw Error('invalid allocation');
 const base=realpathSync(root),repo=realpathSync(repoDir),target=resolve(join(base,'job-'+taskId));
 if(!inside(base,target)||existsSync(target))throw Error('target already exists or outside root');
 ensureWorktreeTable(db);
 const prior=db.prepare('SELECT task_id,state FROM managed_worktrees WHERE task_id=? OR path=?').get(taskId,target);
 if(prior)throw Error('worktree already registered');
 const result=gitRunner(['worktree','add','--detach',target,baseSha],repo);
 if(result.status!==0)throw Error('worktree create failed');
 try{registerWorktree(db,{taskId,path:target,branch,root:base});}
 catch(e){throw Error('worktree created but registry uncertain; manual reconciliation required',{cause:e});}
 return {taskId,path:target,baseSha,state:'active'};
}
export function listManagedWorktrees(db){
 ensureWorktreeTable(db);
 return db.prepare('SELECT task_id AS taskId,path,state,updated_at AS updatedAt FROM managed_worktrees ORDER BY task_id').all();
}
