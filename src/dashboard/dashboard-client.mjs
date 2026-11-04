const el=id=>document.getElementById(id);
let token='',abort,refreshTimer,connectGeneration=0,pendingConnect;
const show=(parent,items,mapper)=>{parent.replaceChildren(...items.map(mapper));};
const card=(title,details,url)=>{const a=document.createElement('article'),b=document.createElement('strong'),p=document.createElement('p');b.textContent=title;p.textContent=details;a.append(b,p);if(typeof url==='string' && /^https:\/\/github\.com\/[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+\/(?:issues|pull|actions\/runs)\/[0-9]+(?:\/files)?$/.test(url)){const l=document.createElement('a');l.href=url;l.target='_blank';l.rel='noopener noreferrer';l.textContent='GitHub';a.append(l);}return a;};
async function read(path,signal,authToken=token){
 const r=await fetch(path,{headers:{Authorization:'Bearer '+authToken},signal,cache:'no-store'});
 if(!r.ok)throw Error('Status unavailable ('+r.status+')');return r.json();
}
async function loadSnapshot(signal,authToken=token){
 const [jobs,github]=await Promise.all([read('/api/jobs',signal,authToken),read('/api/github',signal,authToken)]);
 return {jobs,github};
}
function renderSnapshot({jobs,github}){
 show(el('jobs'),jobs.jobs,j=>card(j.kind+' · '+j.state,j.id+' · '+j.updatedAt));
 const items=[...github.issues.map(x=>({...x,type:'Issue'})),...github.pullRequests.map(x=>({...x,type:'PR'})),...github.ci.map(x=>({type:'CI',title:x.name,state:x.conclusion||x.status,url:x.url}))];
 show(el('github'),items.slice(0,60),x=>card(x.type+' · '+x.title,x.state||'unknown',x.type==='PR' && x.url && /^https:\/\/github\.com\/[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+\/pull\/[0-9]+$/.test(x.url)?x.url+'/files':x.url));
}
async function refresh(signal,authToken=token){
 const snapshot=await loadSnapshot(signal,authToken);
 if(signal.aborted)return false;
 renderSnapshot(snapshot);
 return true;
}
async function stream(signal){
 let cursor=0,lastRefresh=0,reconnects=0;
 while(!signal.aborted){
  try{
   const r=await fetch('/api/stream',{headers:{Authorization:'Bearer '+token,...(cursor?{'Last-Event-ID':String(cursor)}:{})},signal,cache:'no-store'});
   if(!r.ok)throw Error('stream unavailable');
   reconnects=0;
   const reader=r.body.getReader();const decoder=new TextDecoder();let buffer='';
   while(!signal.aborted){
    const part=await reader.read();if(part.done)break;
    buffer+=decoder.decode(part.value,{stream:true});
    let changed=false,index;while((index=buffer.indexOf('\n\n'))>=0){
     if(index>65536)throw Error('stream frame overflow');
     const frame=buffer.slice(0,index);buffer=buffer.slice(index+2);
     const id=frame.match(/^id: ([0-9]+)$/m);if(id)cursor=Number(id[1]);
     if(/^event: reset$/m.test(frame)){cursor=0;changed=true;}
     if(/^event: job$/m.test(frame))changed=true;
    }
    if(buffer.length>65536)throw Error('stream frame overflow');
    if(changed){
     lastRefresh=Date.now();
     try{await refresh(signal);if(!signal.aborted)el('status').textContent='Connected';}catch{if(!signal.aborted)el('status').textContent='Live stream connected; status refresh unavailable';}
    }

   }
  }catch(e){if(!signal.aborted)el('status').textContent='Reconnecting live stream';}
  if(signal.aborted)break;
  reconnects=Math.min(reconnects+1,6);
  await new Promise(resolve=>{
   let finished=false;
   const finish=()=>{if(finished)return;finished=true;clearTimeout(timer);signal.removeEventListener('abort',finish);resolve();};
   if(signal.aborted){resolve();return;}
   const timer=setTimeout(finish,Math.min(1000*2**(reconnects-1),30000));
   signal.addEventListener('abort',finish,{once:true});
   if(signal.aborted)finish();
  });
 }
}
el('connect').onclick=async()=>{
 const enteredToken=el('token').value;
 el('token').value='';
 // A duplicate blank click must not replace a pending authentication attempt.
 if(!enteredToken && pendingConnect)return;
 const candidateToken=enteredToken || token;
 if(!candidateToken){
  if(!pendingConnect)el('status').textContent='Authentication token required';
  return;
 }
 const generation=++connectGeneration;
 const controller=new AbortController();
 if(pendingConnect)pendingConnect.abort();
 pendingConnect=controller;
 try{
  // Validate a candidate before closing an existing authenticated session.
  const snapshot=await loadSnapshot(controller.signal,candidateToken);
  if(controller.signal.aborted||generation!==connectGeneration)return;
  if(abort)abort.abort();
  if(refreshTimer)clearInterval(refreshTimer);
  abort=controller;
  token=candidateToken;
  renderSnapshot(snapshot);
  el('status').textContent='Connected';
  const timer=setInterval(()=>{
   if(controller.signal.aborted||abort!==controller){clearInterval(timer);return;}
   refresh(controller.signal).then(()=>{
    if(!controller.signal.aborted&&abort===controller)el('status').textContent='Connected';
   }).catch(()=>{
    if(!controller.signal.aborted&&abort===controller)el('status').textContent='Status refresh unavailable';
   });
  },30000);
  refreshTimer=timer;
  stream(controller.signal);
 }catch{
  controller.abort();
  if(generation!==connectGeneration)return;
  el('status').textContent=abort&&!abort.signal.aborted?'Connected':'Authentication or service error';
 }finally{
  if(pendingConnect===controller)pendingConnect=undefined;
 }
};
