import {spawnSync} from 'node:child_process';
import {randomUUID} from 'node:crypto';
import {mkdirSync,writeFileSync,readFileSync,existsSync,renameSync} from 'node:fs';
import {join} from 'node:path';
import {homedir} from 'node:os';

const session='mcp-dev-hub-10';
const stateDir=process.env.MCP_DEV_HUB_STATE_DIR || join(homedir(),'.local','state','mcp-dev-hub');
const [action]=process.argv.slice(2);
const run=(args)=>spawnSync('tmux',args,{encoding:'utf8',stdio:['ignore','pipe','pipe']});
const statePath=join(stateDir,'continuity.json');
function save(data){
 mkdirSync(stateDir,{recursive:true,mode:0o700});
 const temp=statePath+'.tmp';
 writeFileSync(temp,JSON.stringify(data,null,2),{mode:0o600});
 renameSync(temp,statePath);
}
function load(){return existsSync(statePath)?JSON.parse(readFileSync(statePath,'utf8')):null;}
function checkTmux(){return run(['has-session','-t','='+session]).status===0;}
function capture(){return run(['capture-pane','-p','-S','-200','-t','='+session+':check']).stdout;}
function resultFromPane(state){
 if(!state||state.status!=='running'||!checkTmux())return state;
 const output=capture();
 const match=output.match(new RegExp('END '+state.id+' exit=([0-9]+)'));
 if(match){
   const finished={...state,status:Number(match[1])===0?'succeeded':'failed',exitCode:Number(match[1]),finishedAt:new Date().toISOString()};
   save(finished);return finished;
 }
 return state;
}
if(action==='status'){
 console.log(JSON.stringify({session,tmuxAvailable:checkTmux(),lastRun:resultFromPane(load())},null,2));process.exit(0);
}
if(action==='start'){
 if(!checkTmux()){const r=run(['new-session','-d','-s',session,'-n','continuity']);if(r.status!==0)throw Error('tmux unavailable');}
 console.log('tmux session ready:',session);process.exit(0);
}
if(action==='check'){
 if(!checkTmux())throw Error('tmux session missing; run start first');
 const previous=resultFromPane(load());
 if(previous?.status==='running')throw Error('previous execution unresolved: inspect tmux and reconcile manually');
 const id=randomUUID();
 const data={id,session,kind:'npm-check',status:'running',startedAt:new Date().toISOString()};
 save(data);
 const inner=`printf '%s\\n' 'RUN ${id} npm run check'; source "$HOME/.nvm/nvm.sh" 2>/dev/null || true; npm run check; code=$?; printf 'END ${id} exit=%s\\n' "$code"; exec bash`;
 const exists=run(['list-windows','-t','='+session,'-F','#{window_name}']).stdout.split('\n').includes('check');
 if(exists)run(['kill-window','-t','='+session+':check']);
 const result=run(['new-window','-d','-t','='+session,'-n','check','bash','-lc',inner]);
 if(result.status!==0){save({...data,status:'launch-failed',finishedAt:new Date().toISOString()});throw Error('tmux launch failed');}
 console.log(JSON.stringify({id,status:'launched',session}));process.exit(0);
}
if(action==='reconcile'){
 const state=resultFromPane(load());if(!state||state.status!=='running')throw Error('no unresolved run');
 if(checkTmux()&&run(['list-windows','-t','='+session,'-F','#{window_name}']).stdout.split('\\n').includes('check'))throw Error('tmux check window still exists: cannot mark unknown or allow replay until execution is independently resolved');
 save({...state,status:'unknown',reconciledAt:new Date().toISOString()});
 console.log('marked unknown; review tmux output and test evidence before retry');process.exit(0);
}
throw Error('usage: node scripts/continuity.mjs start|check|status|reconcile');
