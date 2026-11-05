// Install this reviewed, standalone file in a root-owned, non-worktree directory
// before enabling its Worker entrypoint. Running it from a checkout is NOT
// authorization to execute untrusted tests.
import {spawnSync} from 'node:child_process';
import {mkdtempSync, writeFileSync, chmodSync, rmSync, realpathSync, lstatSync, readdirSync} from 'node:fs';
import {join, relative, sep, isAbsolute, resolve} from 'node:path';
import {pathToFileURL} from 'node:url';

const HEAD = /^[0-9a-f]{40}$/;
const TEST = /^[a-z0-9][a-z0-9_.-]*\.test\.(?:mjs|js|cjs)$/;
const FIXED_OS_PATHS = ['/usr', '/bin', '/lib', '/lib64'];
const NODE = '/usr/bin/node';
const GIT = '/usr/bin/git';
const BWRAP = '/usr/bin/bwrap';

function fail(reason) { throw new Error(reason); }
function contained(root, target) {
  const rel=relative(root,target);
  return rel!=='' && rel!=='..' && !rel.startsWith('..'+sep) && !isAbsolute(rel);
}
function exactPath(path) {
  if(typeof path!=='string' || !isAbsolute(path) || resolve(path)!==path) fail('invalid_absolute_path');
  if(realpathSync(path)!==path) fail('symlinked_path');
  return path;
}
function rootOwnedExecutable(path) {
  const original=exactPath(path);
  let p=original;
  while(true){
    const st=lstatSync(p);
    if(st.isSymbolicLink() || st.uid!==0 || (st.mode&0o022)!==0) fail('untrusted_os_binary');
    if(p===original && (!st.isFile()||(st.mode&0o111)===0)) fail('untrusted_os_binary');
    if(p==='/') break;
    p=p.slice(0,p.lastIndexOf('/'))||'/';
  }
  return original;
}
function gitResult(args,dir) {
  const result=spawnSync(GIT,['-C',dir,...args],{
    encoding:'utf8',stdio:['ignore','pipe','pipe'],timeout:12000,maxBuffer:65536,
    env:{PATH:'/usr/bin:/bin',LANG:'C.UTF-8',GIT_CONFIG_NOSYSTEM:'1',
      GIT_CONFIG_GLOBAL:'/dev/null',GIT_OPTIONAL_LOCKS:'0',GIT_TERMINAL_PROMPT:'0'}
  });
  if(result.error||result.status!==0||result.signal)fail('git_preflight_failed');
  return result.stdout.trim();
}
export function validateScope({root,worktree,head}) {
  if(!HEAD.test(head||''))fail('invalid_head');
  const base=exactPath(root),dir=exactPath(worktree);
  if(!contained(base,dir))fail('outside_approved_root');
  if(gitResult(['rev-parse','--show-toplevel'],dir)!==dir)fail('unexpected_worktree');
  if(gitResult(['rev-parse','HEAD'],dir)!==head)fail('head_changed');
  // Tests may run only on a clean, pinned checkout. Unreviewed edits need a
  // separately scoped path, which this minimal read-only runner does not grant.
  if(gitResult(['status','--porcelain','--untracked-files=all'],dir))fail('dirty_checkout');
  const testDir=join(dir,'tests');
  if(realpathSync(testDir)!==testDir||!contained(dir,testDir))fail('untrusted_tests_directory');
  const names=readdirSync(testDir).filter(n=>TEST.test(n)).sort();
  if(!names.length||names.length>300)fail('invalid_test_set');
  for(const name of names) {
    const file=join(testDir,name),st=lstatSync(file);
    if(!st.isFile()||st.isSymbolicLink()||realpathSync(file)!==file)fail('untrusted_test_file');
  }
  return {worktree:dir,head,testFiles:names.map(n=>'tests/'+n)};
}
// All untrusted test source executes only inside the namespace: no host HOME,
// no Worker state, no SSH/model/GitHub credentials, and no external network.
// The synthetic hosts file permits localhost tests on isolated loopback only.
export function sandboxArgs({worktree,testFiles,hosts}) {
  const argv=['--clearenv','--unshare-all','--die-with-parent'];
  for(const path of FIXED_OS_PATHS)argv.push('--ro-bind',path,path);
  argv.push('--proc','/proc','--dev','/dev','--tmpfs','/tmp',
    '--dir','/etc','--ro-bind',hosts,'/etc/hosts','--dir','/home',
    '--ro-bind',worktree,'/work','--chdir','/work',
    '--setenv','PATH','/usr/bin:/bin',
    '--setenv','HOME','/home/isolated',
    '--setenv','CI','1',
    '--',NODE,'--test','--test-reporter=tap',...testFiles);
  return argv;
}
// Prefer the final TAP epilogue. Earlier TAP-like lines can be nested test
// output and must not be mistaken for the overall result.
export function verifiedTapSummary(stdout,minTests=1) {
  if(typeof stdout!=='string'||!Number.isSafeInteger(minTests)||minTests<1)return null;
  const lines=stdout.trimEnd().split(/\r?\n/);
  const tail=lines.slice(-10);
  const counts=Object.fromEntries(['tests','pass','fail','cancelled','skipped'].map(key=>{
    const values=tail.filter(line=>new RegExp('^# '+key+' [0-9]+
  const scope=validateScope({root,worktree,head});
  rootOwnedExecutable(BWRAP);
  rootOwnedExecutable(NODE);
  rootOwnedExecutable(GIT);
  if(!Number.isSafeInteger(timeoutMs)||timeoutMs<1000||timeoutMs>120000)fail('invalid_timeout');
  const temp=mkdtempSync('/tmp/mcp-dev-hub-hosts-');
  try {
    const hosts=join(temp,'hosts');
    writeFileSync(hosts,'127.0.0.1 localhost\n::1 localhost\n',{mode:0o400,flag:'wx'});
    chmodSync(hosts,0o400);
    const result=spawnSync(BWRAP,sandboxArgs({...scope,hosts}),{
      encoding:'utf8',stdio:['ignore','pipe','pipe'],timeout:timeoutMs,
      maxBuffer:512*1024,env:{PATH:'/usr/bin:/bin',LANG:'C.UTF-8'}
    });
    // Never echo untrusted test output into a public log.
    if(result.error?.code==='ETIMEDOUT')return {state:'unknown',reason:'timeout'};
    if(result.error||result.signal)return {state:'unknown',reason:'runtime_uncertain'};
    if(result.status!==0)return {state:'failed',reason:'test_or_isolation_failure'};
    const count=verifiedTapSummary(result.stdout,scope.testFiles.length);
    if(count===null)return {state:'blocked',reason:'test_summary_not_verified'};
    return {state:'succeeded',head,tests:count};
  } finally {rmSync(temp,{recursive:true,force:true});}
}
if(process.argv[1] && import.meta.url===pathToFileURL(resolve(process.argv[1])).href) {
  try {
    if(process.argv.length!==5)fail('usage_rejected');
    const outcome=runIsolatedRepoCheck({
      root:process.argv[2],worktree:process.argv[3],head:process.argv[4]
    });
    process.stdout.write(JSON.stringify(outcome)+'\n');
    if(outcome.state!=='succeeded')process.exitCode=75;
  } catch {
    process.stdout.write(JSON.stringify({state:'blocked',reason:'preflight_rejected'})+'\n');
    process.exitCode=75;
  }
}
).test(line));
    return [key,values.length===1?Number(values[0].slice(key.length+3)):null];
  }));
  if(Object.values(counts).some(n=>!Number.isSafeInteger(n)) ||
    counts.tests<minTests||counts.pass!==counts.tests ||
    counts.fail!==0||counts.cancelled!==0||counts.skipped!==0)return null;
  return counts.tests;
}
export function runIsolatedRepoCheck({root,worktree,head,timeoutMs=90000}) {
  const scope=validateScope({root,worktree,head});
  rootOwnedExecutable(BWRAP);
  rootOwnedExecutable(NODE);
  rootOwnedExecutable(GIT);
  if(!Number.isSafeInteger(timeoutMs)||timeoutMs<1000||timeoutMs>120000)fail('invalid_timeout');
  const temp=mkdtempSync('/tmp/mcp-dev-hub-hosts-');
  try {
    const hosts=join(temp,'hosts');
    writeFileSync(hosts,'127.0.0.1 localhost\n::1 localhost\n',{mode:0o400,flag:'wx'});
    chmodSync(hosts,0o400);
    const result=spawnSync(BWRAP,sandboxArgs({...scope,hosts}),{
      encoding:'utf8',stdio:['ignore','pipe','pipe'],timeout:timeoutMs,
      maxBuffer:512*1024,env:{PATH:'/usr/bin:/bin',LANG:'C.UTF-8'}
    });
    // Never echo untrusted test output into a public log.
    if(result.error?.code==='ETIMEDOUT')return {state:'unknown',reason:'timeout'};
    if(result.error||result.signal)return {state:'unknown',reason:'runtime_uncertain'};
    if(result.status!==0)return {state:'failed',reason:'test_or_isolation_failure'};
    const pass=/# pass (\d+)/.exec(result.stdout||'');
    const failCount=/# fail (\d+)/.exec(result.stdout||'');
    const tests=/# tests (\d+)/.exec(result.stdout||'');
    if(!pass||!failCount||!tests||Number(failCount[1])!==0||
      Number(pass[1])!==Number(tests[1])||Number(tests[1])<1)
      return {state:'blocked',reason:'test_summary_not_verified'};
    return {state:'succeeded',head,tests:Number(tests[1])};
  } finally {rmSync(temp,{recursive:true,force:true});}
}
if(process.argv[1] && import.meta.url===pathToFileURL(resolve(process.argv[1])).href) {
  try {
    if(process.argv.length!==5)fail('usage_rejected');
    const outcome=runIsolatedRepoCheck({
      root:process.argv[2],worktree:process.argv[3],head:process.argv[4]
    });
    process.stdout.write(JSON.stringify(outcome)+'\n');
    if(outcome.state!=='succeeded')process.exitCode=75;
  } catch {
    process.stdout.write(JSON.stringify({state:'blocked',reason:'preflight_rejected'})+'\n');
    process.exitCode=75;
  }
}
