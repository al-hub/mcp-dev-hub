import {spawn} from 'node:child_process';
import {accessSync,constants} from 'node:fs';
import {join} from 'node:path';
import {homedir} from 'node:os';

// A smoke test is one bounded read-only request, not a review or permission grant.
const home=homedir();
const providers=[
 {name:'agy',bin:process.env.MCP_DEV_HUB_AGY_BIN||join(home,'.local','bin','agy'),args:['--mode','plan','--sandbox','--print-timeout','25s','--print=Reply with exactly READY']},
 {name:'codex',bin:process.env.MCP_DEV_HUB_CODEX_BIN||join(home,'.nvm','versions','node','v24.15.0','bin','codex'),args:['exec','--sandbox','read-only','Reply with exactly READY']}
];
if(process.env.MCP_DEV_HUB_ENABLE_OPENCODE_FALLBACK==='1')
 providers.push({name:'opencode',bin:process.env.MCP_DEV_HUB_OPENCODE_BIN||join(home,'.opencode','bin','opencode'),args:['run','--model','opencode/deepseek-v4.1-flash-free','Reply with exactly READY']});
const timeoutMs=Number(process.env.MCP_DEV_HUB_CLI_SMOKE_TIMEOUT_MS||24000);
if(!Number.isSafeInteger(timeoutMs)||timeoutMs<1000||timeoutMs>60000)throw Error('INVALID_SMOKE_TIMEOUT');
function run(provider){
 return new Promise(resolve=>{
  try{accessSync(provider.bin,constants.X_OK);}catch{return resolve({status:'unavailable'});}
  let done=false,buffer='',timedOut=false;
  const child=spawn(provider.bin,provider.args,{shell:false,stdio:['ignore','pipe','pipe'],env:{PATH:process.env.PATH||'/usr/bin:/bin',HOME:home,LANG:'C.UTF-8',CI:'1'}});
  const timer=setTimeout(()=>{timedOut=true;child.kill('SIGTERM');setTimeout(()=>child.kill('SIGKILL'),1500).unref();},timeoutMs);
  const finish=(status)=>{if(done)return;done=true;clearTimeout(timer);resolve({status});};
  child.stdout.on('data',b=>{buffer=(buffer+b.toString()).slice(-8192);});
  child.stderr.on('data',b=>{buffer=(buffer+b.toString()).slice(-8192);});
  child.on('error',()=>finish('unavailable'));
  child.on('close',code=>finish(timedOut?'timeout':code===0&&/^\s*READY\s*$/m.test(buffer)?'ready':'failed'));
 });
}
let success=false;
for(const p of providers){
 const result=await run(p);
 process.stdout.write('CLI_SMOKE '+p.name+' '+result.status+'\n');
 if(result.status==='ready'){success=true;break;}
}
process.stdout.write(success?'CLI_READY\n':'CLI_FAILED\n');
process.exitCode=success?0:1;
