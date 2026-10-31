import {spawn} from 'node:child_process';
import {accessSync,constants} from 'node:fs';
import {join} from 'node:path';
import {homedir} from 'node:os';
const executable=process.env.MCP_DEV_HUB_OPENCODE_BIN || join(homedir(),'.opencode','bin','opencode');
try {accessSync(executable,constants.X_OK);}
catch {process.stderr.write('CLI_UNAVAILABLE\n');process.exit(2);}
const args=['run','--model','opencode/deepseek-v4.1-flash-free','Reply with exactly READY'];
const child=spawn(executable,args,{shell:false,stdio:['ignore','pipe','pipe'],env:{...process.env,CI:'1'}});
let ended=false,timedOut=false;
const timeout=setTimeout(()=>{timedOut=true;child.kill('SIGTERM');setTimeout(()=>child.kill('SIGKILL'),1500).unref();},45000);
let output='';
for(const stream of [child.stdout,child.stderr])stream.on('data',chunk=>{output+=chunk.toString().slice(0,2048);if(output.length>8192)output=output.slice(-8192);});
child.on('error',()=>{if(ended)return;ended=true;clearTimeout(timeout);process.stderr.write('CLI_UNAVAILABLE\n');process.exitCode=2;});
child.on('close',code=>{if(ended)return;ended=true;clearTimeout(timeout);const valid=!timedOut&&code===0&&/\bREADY\b/.test(output);process.stdout.write(valid?'CLI_READY\n':'CLI_FAILED\n');process.exitCode=valid?0:1;});
