const el=id=>document.getElementById(id);
let token='',abort,refreshTimer;
const show=(parent,items,mapper)=>{parent.replaceChildren(...items.map(mapper));};
const card=(title,details,url)=>{const a=document.createElement('article'),b=document.createElement('strong'),p=document.createElement('p');b.textContent=title;p.textContent=details;a.append(b,p);if(typeof url==='string' && /^https:\/\/github\.com\/[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+\/(?:issues|pull|actions\/runs)\/[0-9]+(?:\/files)?$/.test(url)){const l=document.createElement('a');l.href=url;l.target='_blank';l.rel='noopener noreferrer';l.textContent='GitHub';a.append(l);}return a;};
async function read(path,signal){
 const r=await fetch(path,{headers:{Authorization:'Bearer '+token},signal,cache:'no-store'});
 if(!r.ok)throw Error('Status unavailable ('+r.status+')');return r.json();
}
async function refresh(signal){
 const [jobs,github]=await Promise.all([read('/api/jobs',signal),read('/api/github',signal)]);
 show(el('jobs'),jobs.jobs,j=>card(j.kind+' · '+j.state,j.id+' · '+j.updatedAt));
 const items=[...github.issues.map(x=>({...x,type:'Issue'})),...github.pullRequests.map(x=>({...x,type:'PR'})),...github.ci.map(x=>({type:'CI',title:x.name,state:x.conclusion||x.status,url:x.url}))];
 show(el('github'),items.slice(0,60),x=>card(x.type+' · '+x.title,x.state||'unknown',x.type==='PR' && x.url && /^https:\/\/github\.com\/[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+\/pull\/[0-9]+$/.test(x.url)?x.url+'/files':x.url));
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
     if(frame.includes('event: reset')){cursor=0;changed=true;}
     if(frame.includes('event: job'))changed=true;
    }
    if(buffer.length>65536)throw Error('stream frame overflow');
    if(changed){
     lastRefresh=Date.now();
     try{await refresh(signal);}catch{if(!signal.aborted)el('status').textContent='Live stream connected; status refresh unavailable';}
    }

   }
  }catch(e){if(!signal.aborted)el('status').textContent='Reconnecting live stream';}
  if(signal.aborted)break;
  reconnects=Math.min(reconnects+1,6);
  await new Promise(resolve=>setTimeout(resolve,Math.min(1000*2**(reconnects-1),30000)));
 }
}
el('connect').onclick=async()=>{
 if(abort)abort.abort();if(refreshTimer)clearInterval(refreshTimer);refreshTimer=undefined;abort=new AbortController();token=el('token').value || token;el('token').value='';
 try{await refresh(abort.signal);el('status').textContent='Connected';refreshTimer=setInterval(()=>{if(abort.signal.aborted){clearInterval(refreshTimer);return;}refresh(abort.signal).catch(()=>{if(!abort.signal.aborted)el('status').textContent='Status refresh unavailable';});},30000);stream(abort.signal);}
 catch{el('status').textContent='Authentication or service error';token='';}
};
