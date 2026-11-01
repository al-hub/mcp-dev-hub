// One-shot, fail-closed AI development executor. Run only from a Worker-owned
// SHA-pinned isolated worktree. No shell, no auto replay, no approval inference.
import {spawnSync} from 'node:child_process';
import {realpathSync} from 'node:fs';
import {resolve} from 'node:path';
import {openDb} from './worker.mjs';
import {transitionDevelopment,authorizeCommit} from '../src/jobs/ai-development-claims.mjs';
const sha=/^[a-f0-9]{40}$/;
const idre=/^fix-pr-[a-f0-9]{12}$/;
const run=(bin,args,cwd,ms)=>spawnSync(bin,args,{cwd,shell:false,encoding:'utf8',stdio:['ignore','pipe','pipe'],timeout:ms,maxBuffer:262144,env:{PATH:process.env.PATH,HOME:process.env.HOME,CI:'1',LANG:'C.UTF-8'}});
const git=(args,cwd)=>{const r=spawnSync('git',args,{cwd,shell:false,encoding:'utf8',stdio:['ignore','pipe','pipe'],timeout:12000,maxBuffer:262144});if(r.status!==0||r.error)throw Error('git precondition or operation failed');return r.stdout.trim();};
export function preflight({jobId,headSha,repoDir,worktree,approvedRoot,branch}){
 if(!idre.test(jobId)||!sha.test(headSha)||jobId!=='fix-pr-'+headSha.slice(0,12))throw Error('invalid identity');
 if(!/^task\/fix-pr-[a-f0-9]{12}$/.test(branch))throw Error('invalid branch');
 if(!approvedRoot||!worktree||!repoDir)throw Error('unconfigured execution scope');
 const root=realpathSync(approvedRoot),dir=realpathSync(worktree),repo=realpathSync(repoDir);
 if(!dir.startsWith(root+'/')||dir===repo)throw Error('unapproved worktree');
 if(git(['rev-parse','HEAD'],dir)!==headSha)throw Error('stale SHA');
 if(git(['status','--porcelain'],dir))throw Error('dirty worktree');
 if(git(['branch','--show-current'],dir)!==branch)throw Error('unexpected branch');
 return dir;
}
export function executeOnce({db,jobId,headSha,repoDir,worktree,approvedRoot,branch,prompt,agyBin,codexBin,allowPush=false}){
 if(process.env.MCP_DEV_HUB_ENABLE_AI_WRITE!=='1')return {state:'disabled'};
 const dir=preflight({jobId,headSha,repoDir,worktree,approvedRoot,branch});
 const claim=db.prepare('SELECT phase,head_sha FROM ai_development_claims WHERE job_id=?').get(jobId);
 if(claim?.head_sha!==headSha||claim?.phase!=='claimed')return {state:'not_claimed'};
 // Claim the one execution before launching any process. Unknown results stay blocked.
 if(!transitionDevelopment(db,{jobId,headSha,from:'claimed',to:'running'}))return {state:'duplicate'};
 const agy=run(agyBin,['--mode','accept-edits','--sandbox','--print-timeout','65s','--print='+prompt],dir,80000);
 if(agy.status!==0||agy.error){transitionDevelopment(db,{jobId,headSha,from:'running',to:'blocked'});return {state:'agy_failed'};}
 const changed=git(['diff','--name-only'],dir).split('\n').filter(Boolean);
 if(!changed.length||changed.some(p=>!/^tests\/[a-z0-9][a-z0-9_.-]*\.test\.mjs$/.test(p)))return {state:'unsafe_diff'};
 if(git(['ls-files','--others','--exclude-standard'],dir))return {state:'untracked_files'};
 if(!transitionDevelopment(db,{jobId,headSha,from:'running',to:'edited'}))return {state:'stale_claim'};
 const test=run('npm',['run','check'],dir,60000);
 if(test.status!==0||test.error)return {state:'tests_failed'};
 if(!transitionDevelopment(db,{jobId,headSha,from:'edited',to:'tested'}))return {state:'stale_claim'};
 const codex=run(codexBin,['exec','--sandbox','read-only','Review only the working-tree diff of the current git checkout for concrete defects. Say exactly REVIEW_PASS if no defects. Do not edit files.'],dir,80000);
 if(codex.status!==0||codex.error||codex.stdout.trim()!=='REVIEW_PASS')return {state:'codex_not_passed'};
 if(!transitionDevelopment(db,{jobId,headSha,from:'tested',to:'reviewed'}))return {state:'stale_claim'};
 // Verify no second writer changed the checkout during read-only review.
 if(git(['rev-parse','HEAD'],dir)!==headSha)return {state:'stale_sha'};
 const after=git(['diff','--name-only'],dir).split('\n').filter(Boolean);
 if(JSON.stringify(changed)!==JSON.stringify(after))return {state:'changed_during_review'};
 // The guarded commit is opt-in and never pushes to a protected/shared PR branch.
 if(!allowPush||process.env.MCP_DEV_HUB_ENABLE_AI_PUSH!=='1')return {state:'reviewed_dry_run',changed};
 if(!authorizeCommit(db,{jobId,headSha,verifiedBaseSha:git(['rev-parse','HEAD'],dir),testsPassed:true,codexReviewed:true,changedPaths:changed}))return {state:'commit_denied'};
 if(!transitionDevelopment(db,{jobId,headSha,from:'reviewed',to:'pushing'}))return {state:'commit_claim_lost'};
 git(['add','--',...changed],dir);
 git(['commit','-m','test: AI-reviewed bounded remediation'],dir);
 // Push a distinct task branch only; never force push or update the PR head.
 git(['push','--porcelain','origin','HEAD:refs/heads/'+branch],dir);
 transitionDevelopment(db,{jobId,headSha,from:'pushing',to:'pushed'});
 return {state:'pushed_task_branch',branch,changed};
}
if(import.meta.url===new URL('file://'+resolve(process.argv[1]||'/dev/null')).href){
 const jobId=process.env.MCP_DEV_HUB_AI_JOB_ID;
 const headSha=process.env.MCP_DEV_HUB_AI_HEAD_SHA;
 const worktree=process.env.MCP_DEV_HUB_AI_WORKTREE;
 const branch=process.env.MCP_DEV_HUB_AI_BRANCH;
 const db=openDb();
 try {
  const result=executeOnce({db,jobId,headSha,worktree,branch,
   repoDir:process.env.MCP_DEV_HUB_WORKTREE_REPO,approvedRoot:process.env.MCP_DEV_HUB_WORKTREE_ROOT,
   prompt:'Improve a single regression test related to the findings. Edit only tests/*.test.mjs. Never edit production files, run tools, or access secrets.',
   agyBin:process.env.MCP_DEV_HUB_AGY_BIN||'agy',
   codexBin:process.env.MCP_DEV_HUB_CODEX_BIN||'codex',
   allowPush:true});
  process.stdout.write(JSON.stringify(result)+'\n');
  if(result.state!=='pushed_task_branch'&&result.state!=='reviewed_dry_run')process.exitCode=75;
 }finally{db.close();}
}
