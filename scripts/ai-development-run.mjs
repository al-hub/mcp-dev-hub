// One-shot, fail-closed AI development executor. Run only from a Worker-owned
// SHA-pinned isolated worktree. No shell, no auto replay, no approval inference.
import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {realpathSync} from 'node:fs';
import {resolve} from 'node:path';
import {openDb} from './worker.mjs';
import {transitionDevelopment,authorizeCommit,finishDevelopment} from '../src/jobs/ai-development-claims.mjs';
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
 if(realpathSync(git(['rev-parse','--show-toplevel'],dir))!==dir)throw Error('git worktree root mismatch');
 const actualHead=git(['rev-parse','HEAD'],dir);
 if(actualHead!==headSha)throw Error('stale SHA expected='+headSha.slice(0,8)+' actual='+actualHead.slice(0,8));
 if(git(['status','--porcelain'],dir))throw Error('dirty worktree');
 if(git(['branch','--show-current'],dir)!==branch)throw Error('unexpected branch');
 return dir;
}
export function executeOnce({db,jobId,headSha,repoDir,worktree,approvedRoot,branch,prompt,agyBin,codexBin,npmBin='npm',allowPush=false}){
 if(process.env.MCP_DEV_HUB_ENABLE_AI_WRITE!=='1')return {state:'disabled'};
 const claim=db.prepare('SELECT phase,head_sha FROM ai_development_claims WHERE job_id=?').get(jobId);
 if(claim?.head_sha!==headSha||claim?.phase!=='claimed')return {state:'not_claimed'};
 let dir;
 try{dir=preflight({jobId,headSha,repoDir,worktree,approvedRoot,branch});}
 catch{
   finishDevelopment(db,{jobId,headSha,from:'claimed',to:'blocked',reason:'preflight_rejected'});
   return {state:'preflight_rejected'};
 }
 // Consume the sole execution claim before launching AGY; never replay uncertain effects.
 if(!transitionDevelopment(db,{jobId,headSha,from:'claimed',to:'running'}))return {state:'duplicate'};
 let phase='running';
 const advance=(to)=>{
   if(!transitionDevelopment(db,{jobId,headSha,from:phase,to}))return false;
   phase=to;return true;
 };
 const stop=(state,to='failed')=>{
   if(!finishDevelopment(db,{jobId,headSha,from:phase,to,reason:state}))
     return {state:'stale_claim'};
   return {state};
 };
 try{
   const agy=run(agyBin,['--mode','accept-edits','--sandbox','--print-timeout','65s','--print='+prompt],dir,80000);
   if(agy.error?.code==='ETIMEDOUT')return stop('agy_timeout','unknown');
   if(agy.status!==0||agy.error)return stop('agy_failed');
   const changed=git(['diff','--name-only'],dir).split('\n').filter(Boolean);
   if(!changed.length)return stop('no_diff');
   if(changed.some(p=>!/^tests\/[a-z0-9][a-z0-9_.-]*\.test\.mjs$/.test(p)))return stop('unsafe_diff','blocked');
   if(git(['ls-files','--others','--exclude-standard'],dir))return stop('untracked_files','blocked');
   const changeDigest=createHash('sha256').update(git(['diff','--binary'],dir)).digest('hex');
   if(!advance('edited'))return {state:'stale_claim'};
   const check=run(npmBin,['run','check'],dir,60000);
   if(check.error?.code==='ETIMEDOUT')return stop('tests_timeout','unknown');
   if(check.status!==0||check.error)return stop('tests_failed');
   if(!advance('tested'))return {state:'stale_claim'};
   // Verdict must be anchored to the exact starting SHA and changed file list.
   const expected={baseSha:headSha,files:changed};
   const reviewPrompt='Review only the current working-tree diff without editing or running commands. Return ONLY a JSON object with verdict APPROVE or REJECT, baseSha equal to '+expected.baseSha+', files equal to '+JSON.stringify(expected.files)+', and findings as an array. Approve only if there are no concrete defects.';
   const codex=run(codexBin,['exec','--sandbox','read-only',reviewPrompt],dir,80000);
   if(codex.error?.code==='ETIMEDOUT')return stop('codex_timeout','unknown');
   if(codex.status!==0||codex.error)return stop('codex_failed');
   let verdict;
   try{verdict=JSON.parse(codex.stdout.trim());}catch{return stop('codex_invalid','blocked');}
   if(!verdict || verdict.verdict!=='APPROVE'||verdict.baseSha!==headSha||
      JSON.stringify(verdict.files)!==JSON.stringify(changed)||
      !Array.isArray(verdict.findings)||verdict.findings.length!==0)
     return stop('codex_rejected','blocked');
   if(git(['rev-parse','HEAD'],dir)!==headSha)return stop('stale_sha','unknown');
   const after=git(['diff','--name-only'],dir).split('\n').filter(Boolean);
   if(JSON.stringify(changed)!==JSON.stringify(after)||
      createHash('sha256').update(git(['diff','--binary'],dir)).digest('hex')!==changeDigest)
     return stop('changed_during_review','unknown');
   if(git(['ls-files','--others','--exclude-standard'],dir))return stop('untracked_during_review','blocked');
   if(!advance('reviewed'))return {state:'stale_claim'};
   if(!allowPush||process.env.MCP_DEV_HUB_ENABLE_AI_PUSH!=='1')return stop('push_disabled','blocked');
   if(!authorizeCommit(db,{jobId,headSha,verifiedBaseSha:git(['rev-parse','HEAD'],dir),testsPassed:true,codexReviewed:true,changedPaths:changed}))
     return stop('commit_denied','blocked');
   if(!advance('pushing'))return {state:'stale_claim'};
   // Commit/push may have occurred even if a later process reports an error.
   // Preserve the worktree and require manual reconciliation on any uncertainty.
   git(['add','--',...changed],dir);
   git(['commit','-m','test: AI-reviewed bounded remediation'],dir);
   const pushedSha=git(['rev-parse','HEAD'],dir);
   git(['push','--porcelain','origin','HEAD:refs/heads/'+branch],dir);
   const remote=git(['ls-remote','--heads','origin','refs/heads/'+branch],dir);
   if(!remote.startsWith(pushedSha+'\t'))return stop('push_unconfirmed','unknown');
   if(!transitionDevelopment(db,{jobId,headSha,from:'pushing',to:'pushed'}))return {state:'push_claim_uncertain'};
   return {state:'pushed_task_branch',branch,changed};
 }catch{
   return stop(phase==='pushing'?'push_unconfirmed':'execution_uncertain','unknown');
 }
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
   prompt:'Add one regression test in tests/ai-development-claims.test.mjs: a blocked terminal claim must retain its reason and must not be claimed again. You may read and edit only this test file using file tools. Do not execute shell commands, modify production files, or access secrets.',
   agyBin:process.env.MCP_DEV_HUB_AGY_BIN||'agy',
   codexBin:process.env.MCP_DEV_HUB_CODEX_BIN||'codex',
   allowPush:true});
  process.stdout.write(JSON.stringify(result)+'\n');
  if(result.state!=='pushed_task_branch'&&result.state!=='reviewed_dry_run')process.exitCode=75;
 }finally{db.close();}
}
