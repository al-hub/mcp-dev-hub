// Candidate immutable root-owned controller wrapper for #35.
// This source is NOT active merely because it is in GitHub. A separate,
// independently reviewed, explicitly authorized administrator bootstrap must
// install it as the fixed root-owned ai-github-canary.mjs entrypoint.
// The wrapper itself runs as the unprivileged Worker account, NEVER as root.
import {spawnSync} from 'node:child_process';
import {lstatSync,readlinkSync,realpathSync} from 'node:fs';
import {dirname,join} from 'node:path';
import {fileURLToPath} from 'node:url';

const ROOT='/usr/local/lib/mcp-dev-hub';
const SHA=/^[0-9a-f]{40}$/;
const fail=()=>{throw Error('protected_controller_admission_denied');};
function rootRegular(path){
  const st=lstatSync(path);
  if(!st.isFile()||st.isSymbolicLink()||st.uid!==0||
     (st.mode&0o022)!==0)fail();
}
function rootDirectory(path){
  const st=lstatSync(path);
  if(!st.isDirectory()||st.isSymbolicLink()||st.uid!==0||
     (st.mode&0o022)!==0)fail();
}
function run(){
  // No user-controlled paths or dynamic command/argument substitution.
  const self=fileURLToPath(import.meta.url);
  if(self!==join(ROOT,'ai-github-canary.mjs')||
     process.argv.length!==2)fail();
  for(const path of ['/', '/usr','/usr/local',
                     '/usr/local/lib',ROOT,join(ROOT,'versions')])
    rootDirectory(path);
  rootRegular('/usr/bin/node');
  const pointer=join(ROOT,'current');
  const p=lstatSync(pointer);
  if(!p.isSymbolicLink()||p.uid!==0)fail();
  const target=readlinkSync(pointer);
  const match=/^versions\/([a-f0-9]{40})$/.exec(target);
  if(!match||!SHA.test(match[1]))fail();
  const versionDir=join(ROOT,'versions',match[1]);
  rootDirectory(versionDir);
  const controller=join(versionDir,'ai-github-canary.mjs');
  const policy=join(versionDir,'ai-github-canary-policy.mjs');
  rootRegular(controller);
  rootRegular(policy);
  if(realpathSync(controller)!==controller||
     realpathSync(policy)!==policy)fail();
  // The existing controller's direct-invocation guard requires its own file
  // as process.argv[1]. Do not "import" it from this wrapper.
  const env={...process.env};
  delete env.NODE_OPTIONS;
  delete env.NODE_PATH;
  delete env.NODE_EXTRA_CA_CERTS;
  const child=spawnSync('/usr/bin/node',[controller],{
    shell:false,stdio:'inherit',env
  });
  if(typeof child.status==='number')return child.status;
  return 76; // interrupted/external outcome unknown, never success.
}
try{
  process.exitCode=run();
}catch{
  // No private path, tokens, hostnames or exception messages on stdout.
  process.stdout.write('{"state":"blocked","reason":"protected_entrypoint_guard"}\n');
  process.exitCode=75;
}
