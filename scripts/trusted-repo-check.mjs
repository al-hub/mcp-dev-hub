// Reviewed standalone candidate. Install outside any checkout as a root-owned
// immutable launcher before using this from a Worker. This process does not run
// checkout-controlled scripts directly on the host.
import {spawnSync} from 'node:child_process';
import {
  mkdtempSync,writeFileSync,chmodSync,rmSync,realpathSync,lstatSync,
  mkdirSync,readdirSync,existsSync,readFileSync
} from 'node:fs';
import {join,relative,sep,isAbsolute,resolve,dirname} from 'node:path';
import {tmpdir} from 'node:os';
import {pathToFileURL} from 'node:url';
import {createHash} from 'node:crypto';

const HEAD=/^[0-9a-f]{40}$/;
const TEST=/^[a-z0-9][a-z0-9_.-]*\.test\.(?:mjs|js|cjs|ts)$/;
const OS_PATHS=['/usr','/bin','/lib','/lib64'];
const NODE='/usr/bin/node',GIT='/usr/bin/git',BWRAP='/usr/bin/bwrap',SYSTEMD_RUN='/usr/bin/systemd-run';
function fail(reason){throw new Error(reason);}
function contained(root,target){
  const rel=relative(root,target);
  return rel!==''&&rel!=='..'&&!rel.startsWith('..'+sep)&&!isAbsolute(rel);
}
function exactPath(path){
  if(typeof path!=='string'||!isAbsolute(path)||resolve(path)!==path)fail('invalid_path');
  if(realpathSync(path)!==path)fail('symlinked_path');
  return path;
}
function rootOwnedExecutable(path){
  const value=exactPath(path);
  let p=value;
  while(true){
    const st=lstatSync(p);
    if(st.isSymbolicLink()||st.uid!==0||(st.mode&0o022)!==0)fail('untrusted_os_binary');
    if(p===value&&(!st.isFile()||(st.mode&0o111)===0))fail('untrusted_os_binary');
    if(p==='/')break;
    p=p.slice(0,p.lastIndexOf('/'))||'/';
  }
  return value;
}
function gitData(repoDir,args,limit=1048576){
  // Object plumbing cannot invoke checkout-controlled hooks, filters or tests.
  // Disable Git object replacements and inherited configs/credential helpers.
  const r=spawnSync(GIT,['-c','core.fsmonitor=false','-c','core.hooksPath=/dev/null',
    '-c','protocol.allow=never','-C',repoDir,...args],{
    encoding:null,timeout:12000,maxBuffer:limit,stdio:['ignore','pipe','pipe'],
    env:{PATH:'/usr/bin:/bin',LANG:'C.UTF-8',GIT_CONFIG_GLOBAL:'/dev/null',
      GIT_CONFIG_NOSYSTEM:'1',GIT_NO_REPLACE_OBJECTS:'1',GIT_NO_LAZY_FETCH:'1',
      GIT_OPTIONAL_LOCKS:'0',GIT_TERMINAL_PROMPT:'0'}
  });
  if(r.error||r.signal||r.status!==0)fail('git_object_unavailable');
  return r.stdout;
}
function verifiedGitObject(repo,type,hash,limit){
  if(!['blob','commit','tree'].includes(type)||!HEAD.test(hash))fail('invalid_git_object');
  const data=gitData(repo,['cat-file',type,hash],limit);
  const actual=createHash('sha1').update(type+' '+data.length+'\0').update(data).digest('hex');
  if(actual!==hash)fail('git_object_hash_mismatch');
  return data;
}
export function validateScope({root,worktree,head,repoDir}){
  if(!HEAD.test(head||''))fail('invalid_head');
  const base=exactPath(root),dir=exactPath(worktree),repo=exactPath(repoDir);
  if(!contained(base,dir))fail('outside_approved_root');
  if(!/^tree [0-9a-f]{40}\n/.test(verifiedGitObject(repo,'commit',head,262144).toString('utf8')))
    fail('untrusted_commit');
  return {root:base,worktree:dir,head,repoDir:repo};
}
function validGitName(name){
  if(typeof name!=='string'||name.length<1||name.length>512||
    name.startsWith('/')||name.includes('\\')||name.includes(':')||
    /[\u0000-\u001f\u007f]/.test(name))return false;
  const parts=name.split('/');
  return parts.every(p=>p!==''&&p!=='.'&&p!=='..'&&p!=='.git');
}
export function materializeSnapshot({repoDir,head,destination}){
  if(!HEAD.test(head||''))fail('invalid_head');
  const root=exactPath(destination);
  const commit=verifiedGitObject(repoDir,'commit',head,262144).toString('utf8');
  const tree=/^tree ([0-9a-f]{40})\n/.exec(commit);
  if(!tree)fail('invalid_commit_tree');
  let totalBytes=0,treeCount=0;
  const files=[];
  function walk(oid,prefix,depth){
    if(depth>16||++treeCount>300)fail('unsafe_tree_depth');
    const raw=verifiedGitObject(repoDir,'tree',oid,524288);
    let offset=0;
    while(offset<raw.length){
      const space=raw.indexOf(32,offset);
      if(space<0)fail('invalid_tree_entry');
      const nul=raw.indexOf(0,space+1);
      if(nul<0||nul+21>raw.length)fail('invalid_tree_entry');
      const mode=raw.subarray(offset,space).toString('ascii');
      const name=raw.subarray(space+1,nul).toString('utf8');
      const objectId=raw.subarray(nul+1,nul+21).toString('hex');
      offset=nul+21;
      if(name.includes('/'))fail('invalid_tree_entry');
      const path=prefix?prefix+'/'+name:name;
      if(!validGitName(path))fail('unsafe_tree_entry');
      if(mode==='40000'){walk(objectId,path,depth+1);continue;}
      if(!['100644','100755'].includes(mode))fail('unsafe_tree_entry');
      if(files.length>=300)fail('unsafe_tree_size');
      const blob=verifiedGitObject(repoDir,'blob',objectId,786432);
      totalBytes+=blob.length;
      if(totalBytes>8*1024*1024)fail('unsafe_tree_bytes');
      const target=resolve(join(root,path));
      if(!contained(root,target))fail('tree_path_escape');
      mkdirSync(dirname(target),{recursive:true,mode:0o700});
      writeFileSync(target,blob,{flag:'wx',mode:0o400});
      chmodSync(target,0o400);
      files.push(path);
    }
  }
  walk(tree[1],'',0);
  const testFiles=files.filter(name=>name.startsWith('tests/')&&
    name.split('/').length===2&&TEST.test(name.slice(6)));
  if(!testFiles.length)fail('no_pinned_tests');
  return {testFiles,trackedCount:files.length};
}
export function sandboxArgs({snapshot,testFiles,hosts}){
  const argv=['--clearenv','--unshare-all','--die-with-parent'];
  for(const dir of OS_PATHS)argv.push('--ro-bind',dir,dir);
  argv.push('--proc','/proc','--dev','/dev','--tmpfs','/tmp',
    '--dir','/etc','--ro-bind',hosts,'/etc/hosts','--dir','/sandbox-home',
    '--ro-bind',snapshot,'/work','--chdir','/work',
    '--setenv','PATH','/usr/bin:/bin','--setenv','HOME','/sandbox-home',
    '--setenv','CI','1','--',NODE,'--test','--test-reporter=tap',...testFiles);
  return argv;
}
// Only the final TAP epilogue is authoritative; never accept nested test output
// or a partial/faked pass count as full success.
// Run the entire sandbox under a user-systemd cgroup, not just a timer.
// The systemd-run scope is transient and carries bounded memory, tasks and CPU.
export function resourceScopeArgs(args){
  return ['--user','--scope','--collect','--quiet',
    '-p','MemoryMax=1G','-p','TasksMax=64','-p','CPUQuota=100%',
    BWRAP,...sandboxArgs(args)];
}
export function verifiedTapSummary(stdout,minTests=1){
  if(typeof stdout!=='string'||!Number.isSafeInteger(minTests)||minTests<1)return null;
  const lines=stdout.trimEnd().split(/\r?\n/);
  const end=lines.findLastIndex(line=>line.startsWith('1..')&&
    line.length>3&&[...line.slice(3)].every(c=>c>='0'&&c<='9'));
  if(end<0)return null;
  const tail=lines.slice(end),declared=Number(lines[end].slice(3));
  const counts={};
  for(const key of ['tests','pass','fail','cancelled','skipped']){
    const prefix='# '+key+' ';
    const values=tail.filter(line=>line.startsWith(prefix)&&
      line.length>prefix.length&&
      [...line.slice(prefix.length)].every(c=>c>='0'&&c<='9'));
    counts[key]=values.length===1?Number(values[0].slice(prefix.length)):null;
  }
  if(Object.values(counts).some(n=>!Number.isSafeInteger(n))||
    counts.tests!==declared||counts.tests<minTests||counts.pass!==counts.tests||
    counts.fail!==0||counts.cancelled!==0||counts.skipped!==0)return null;
  return counts.tests;
}
export function runIsolatedRepoCheck({root,worktree,head,repoDir,timeoutMs=90000}){
  const scope=validateScope({root,worktree,head,repoDir});
  rootOwnedExecutable(BWRAP);rootOwnedExecutable(NODE);rootOwnedExecutable(GIT);
  rootOwnedExecutable(SYSTEMD_RUN);
  if(!Number.isSafeInteger(timeoutMs)||timeoutMs<1000||timeoutMs>120000)
    fail('invalid_timeout');
  const temp=mkdtempSync(join(tmpdir(),'mcp-dev-hub-snapshot-'));
  try{
    const source=join(temp,'source'),hosts=join(temp,'hosts');
    mkdirSync(source,{mode:0o700});
    const snapshot=materializeSnapshot({repoDir:scope.repoDir,head,destination:source});
    // Generate the standard loopback address without storing a private-network
    // IP candidate in the public repository.
    writeFileSync(hosts,[127,0,0,1].join('.')+' localhost\n::1 localhost\n',
      {flag:'wx',mode:0o400});
    chmodSync(hosts,0o400);
    const r=spawnSync(SYSTEMD_RUN,resourceScopeArgs({snapshot:source,
      testFiles:snapshot.testFiles,hosts}),{
      encoding:'utf8',stdio:['ignore','pipe','pipe'],timeout:timeoutMs,
      maxBuffer:524288,env:{PATH:'/usr/bin:/bin',LANG:'C.UTF-8'}
    });
    // Never forward untrusted test output or secret guesses to public logs.
    if(r.error?.code==='ETIMEDOUT')return {state:'unknown',reason:'timeout'};
    if(r.error||r.signal)return {state:'unknown',reason:'runtime_uncertain'};
    if(r.status!==0)return {state:'failed',reason:'test_or_isolation_failure'};
    const tests=verifiedTapSummary(r.stdout,snapshot.testFiles.length);
    if(tests===null)return {state:'blocked',reason:'test_summary_not_verified'};
    return {state:'succeeded',head,tests,tracked:snapshot.trackedCount};
  }finally{rmSync(temp,{recursive:true,force:true});}
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href){
  try{
    if(process.argv.length!==6)fail('usage_rejected');
    const outcome=runIsolatedRepoCheck({root:process.argv[2],
      worktree:process.argv[3],head:process.argv[4],repoDir:process.argv[5]});
    process.stdout.write(JSON.stringify(outcome)+'\n');
    if(outcome.state!=='succeeded')process.exitCode=75;
  }catch{
    process.stdout.write(JSON.stringify({state:'blocked',reason:'preflight_rejected'})+'\n');
    process.exitCode=75;
  }
}
