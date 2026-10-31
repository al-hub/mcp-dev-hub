import {spawnSync} from 'node:child_process';
import {randomUUID} from 'node:crypto';
import {mkdirSync,writeFileSync,readFileSync,existsSync} from 'node:fs';
import {join} from 'node:path';
import {homedir} from 'node:os';

const session='mcp-dev-hub-10';
const stateDir=process.env.MCP_DEV_HUB_STATE_DIR || join(homedir(),'.local','state','mcp-dev-hub');
const [action]=process.argv.slice(2);
const run=(args)=>spawnSync('tmux',args,{encoding:'utf8',stdio:['ignore','pipe','pipe']});
const statePath=join(stateDir,'continuity.json');
function save(data){mkdirSync(stateDir,{recursive:true,mode:0o700});writeFileSync(statePath,JSON.stringify(data,null,2),{mode:0o600});}
function load(){return existsSync(statePath)?JSON.parse(readFileSync(statePath,'utf8')):null;}
function checkTmux(){const r=run(['has-session','-t','='+session]);return r.status===0;}
if(action==='status'){
 const state=load();console.log(JSON.stringify({session,tmuxAvailable:checkTmux(),lastRun:state},null,2));process.exit(0);
}
if(action==='start'){
 if(!checkTmux()){const r=run(['new-session','-d','-s',session,'-n','continuity']);if(r.status!==0)throw Error('tmux unavailable');}
 console.log('tmux session ready:',session);process.exit(0);
}
if(action==='check'){
 if(!checkTmux())throw Error('tmux session missing; run start first');
 const previous=load();
 if(previous?.status==='running')throw Error('previous execution unresolved: inspect tmux and reconcile manually');
 const id=randomUUID();
 const data={id,session,kind:'npm-check',status:'running',startedAt:new Date().toISOString()};
 save(data);
 // No shell interpolation or arbitrary command input. Observer sees sanitized fixed command and exit code.
 const inner=`printf '%s\\n' 'RUN ${id} npm run check'; npm run check; code=$?; printf 'END ${id} exit=%s\\n' "$code"; exit "$code"`;
 const result=run(['new-window','-d','-t','='+session,'-n','check','bash','-lc',inner]);
 if(result.status!==0){save({...data,status:'launch-failed',finishedAt:new Date().toISOString()});throw Error('tmux launch failed');}
 console.log(JSON.stringify({id,status:'launched',session}));
 process.exit(0);
}
if(action==='reconcile'){
 const state=load();if(!state||state.status!=='running')throw Error('no unresolved run');
 // Do not infer success from a vanished process; require manual evidence.
 save({...state,status:'unknown',reconciledAt:new Date().toISOString()});
 console.log('marked unknown; review tmux output and test evidence before retry');process.exit(0);
}
throw Error('usage: node scripts/continuity.mjs start|check|status|reconcile');
