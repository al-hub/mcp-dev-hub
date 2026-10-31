import {spawn} from 'node:child_process';
import {accessSync,constants,writeFileSync,mkdirSync,chmodSync} from 'node:fs';
import {join,resolve} from 'node:path';
import {homedir} from 'node:os';
const executable=process.env.MCP_DEV_HUB_OPENCODE_BIN || join(homedir(),'.opencode','bin','opencode');
const jobId=process.env.MCP_DEV_HUB_REVIEW_JOB_ID;
const resultDir=process.env.MCP_DEV_HUB_REVIEW_RESULT_DIR;
if(!jobId || !/^[a-z0-9][a-z0-9_-]{2,63}$/.test(jobId) || !resultDir) {
 process.stderr.write('REVIEW_CONFIGURATION_MISSING\n');process.exit(78);
}
try{accessSync(executable,constants.X_OK);}catch{process.stderr.write('REVIEW_CLI_UNAVAILABLE\n');process.exit(78);}
const prompt='Independently review the current source tree for correctness, security and regression risks. Do not edit files or run commands. Respond with findings, paths and suggested tests. If no findings, explain the evidence and limitations. Do not claim GitHub PR approval.';
const args=['run','--model','opencode/deepseek-v4.1-flash-free',prompt];
let output='',finished=false,timedOut=false;
const child=spawn(executable,args,{shell:false,stdio:['ignore','pipe','pipe'],env:{...process.env,CI:'1'}});
const timer=setTimeout(()=>{timedOut=true;child.kill('SIGTERM');setTimeout(()=>child.kill('SIGKILL'),1500).unref();},120000);
for(const stream of [child.stdout,child.stderr])stream.on('data',b=>{output=(output+b.toString()).slice(-32768);});
function finish(code){if(finished)return;finished=true;clearTimeout(timer);const result={jobId,status:timedOut?'timed_out':code===0&&output.trim()?'completed':'failed',exitCode:code,at:new Date().toISOString(),summary:output.slice(-12000).replace(/(Bearer\s+)[^\s]+/gi,'$1[REDACTED]')};const dir=resolve(resultDir);mkdirSync(dir,{recursive:true,mode:0o700});chmodSync(dir,0o700);writeFileSync(join(dir,jobId+'.json'),JSON.stringify(result),{mode:0o600,flag:'w'});process.stdout.write('REVIEW_RESULT_SAVED '+result.status+'\n');process.exitCode=timedOut?124:code===0&&output.trim()?0:75;}
child.on('error',()=>finish(78));child.on('close',c=>finish(c??75));
