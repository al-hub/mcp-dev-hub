import {spawn} from 'node:child_process';
import {accessSync,constants,readFileSync,writeFileSync,mkdirSync,chmodSync} from 'node:fs';
import {join,resolve} from 'node:path';
import {homedir} from 'node:os';
const attempt=Number(process.env.MCP_DEV_HUB_REVIEW_ATTEMPT || '1');
const provider=attempt===3 && process.env.MCP_DEV_HUB_ENABLE_OPENCODE_FALLBACK==='1'?'opencode':attempt%2===0?'codex':'agy';
const executable=provider==='agy'?(process.env.MCP_DEV_HUB_AGY_BIN || join(homedir(),'.local','bin','agy')):provider==='codex'?(process.env.MCP_DEV_HUB_CODEX_BIN || join(homedir(),'.nvm','versions','node','v24.15.0','bin','codex')):(process.env.MCP_DEV_HUB_OPENCODE_BIN || join(homedir(),'.opencode','bin','opencode'));
const jobId=process.env.MCP_DEV_HUB_REVIEW_JOB_ID;
const resultDir=process.env.MCP_DEV_HUB_REVIEW_RESULT_DIR;
if(!jobId || !/^[a-z0-9][a-z0-9_-]{2,63}$/.test(jobId) || !resultDir || !Number.isInteger(attempt) || attempt<1 || attempt>4) {
 process.stderr.write('REVIEW_CONFIGURATION_MISSING\n');process.exit(78);
}
try{accessSync(executable,constants.X_OK);}catch{process.stderr.write('REVIEW_CLI_UNAVAILABLE\n');process.exit(78);}
const areas=Object.freeze({
 dashboard:['src/dashboard/read-only-server.mjs','src/dashboard/dashboard-client.mjs'],
 worker:['scripts/worker.mjs'],
 worktree:['src/jobs/worktree-allocate.mjs','src/jobs/worktree-cleanup.mjs']
});
const area=process.env.MCP_DEV_HUB_REVIEW_AREA || 'dashboard';
if(!Object.hasOwn(areas,area)){process.stderr.write('INVALID_REVIEW_AREA\\n');process.exit(78);}
const source=areas[area].map(file=>file+'\n'+readFileSync(resolve(file),'utf8').slice(0,26000)).join('\n---\n');
const prompt='Review the attached code only. Identify up to three concrete defects or say no findings. Do not use tools, edit files or execute commands. Return REVIEW_FINDINGS: with findings or REVIEW_INCOMPLETE if source is insufficient. This is not GitHub approval.\n'+source;
const args=provider==='agy'?['--mode','plan','--sandbox','--print-timeout','65s','--print='+prompt]:provider==='codex'?['exec','--sandbox','read-only',prompt]:['run','--model','opencode/deepseek-v4.1-flash-free',prompt];
let output='',finished=false,timedOut=false;
const child=spawn(executable,args,{shell:false,stdio:['ignore','pipe','pipe'],env:{PATH:process.env.PATH || '/usr/bin:/bin',HOME:homedir(),LANG:'C.UTF-8',CI:'1'}});
const timer=setTimeout(()=>{timedOut=true;child.kill('SIGTERM');setTimeout(()=>child.kill('SIGKILL'),1500).unref();},75000);
for(const stream of [child.stdout,child.stderr])stream.on('data',b=>{output=(output+b.toString()).slice(-32768);});
function finish(code){if(finished)return;finished=true;clearTimeout(timer);const result={jobId,attempt,provider,status:timedOut?'timed_out':code===0&&/REVIEW_FINDINGS:/i.test(output)&&!/REVIEW_INCOMPLETE|no output produced|review incomplete|unable to inspect|permission.*auto-denied/i.test(output)?'completed':'failed',exitCode:code,at:new Date().toISOString(),summary:output.slice(-12000).replace(/(Bearer\s+)[^\s]+/gi,'$1[REDACTED]')};const dir=resolve(resultDir);mkdirSync(dir,{recursive:true,mode:0o700});chmodSync(dir,0o700);writeFileSync(join(dir,jobId+'-attempt-'+attempt+'.json'),JSON.stringify(result),{mode:0o600,flag:'w'});process.stdout.write('REVIEW_RESULT_SAVED '+result.status+'\n');process.exitCode=timedOut?124:result.status==='completed'?0:75;}
child.on('error',()=>finish(78));child.on('close',c=>finish(c??75));
