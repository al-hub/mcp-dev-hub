const el=id=>document.getElementById(id);
let token='',abort;
const show=(parent,items,mapper)=>{parent.replaceChildren(...items.map(mapper));};
const card=(title,details)=>{const a=document.createElement('article'),b=document.createElement('strong'),p=document.createElement('p');b.textContent=title;p.textContent=details;a.append(b,p);return a;};
async function read(path,signal){
 const r=await fetch(path,{headers:{Authorization:'Bearer '+token},signal,cache:'no-store'});
 if(!r.ok)throw Error('Status unavailable ('+r.status+')');return r.json();
}
async function refresh(signal){
 const [jobs,github]=await Promise.all([read('/api/jobs',signal),read('/api/github',signal)]);
 show(el('jobs'),jobs.jobs,j=>card(j.kind+' · '+j.state,j.id+' · '+j.updatedAt));
 const items=[...github.issues.map(x=>({...x,type:'Issue'})),...github.pullRequests.map(x=>({...x,type:'PR'})),...github.ci.map(x=>({type:'CI',title:x.name,state:x.conclusion||x.status}))];
 show(el('github'),items.slice(0,60),x=>card(x.type+' · '+x.title,x.state||'unknown'));
}
async function stream(signal){
 let cursor=0,lastRefresh=0;
 while(!signal.aborted){
  try{
   const r=await fetch('/api/stream',{headers:{Authorization:'Bearer '+token,...(cursor?{'Last-Event-ID':String(cursor)}:{})},signal,cache:'no-store'});
   if(!r.ok)throw Error('stream unavailable');
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
    if(changed && Date.now()-lastRefresh>=1000){
     lastRefresh=Date.now();
     try{await refresh(signal);}catch{if(!signal.aborted)el('status').textContent='Live stream connected; status refresh unavailable';}
    }

   }
  }catch(e){if(!signal.aborted)el('status').textContent='Disconnected; retry with Connect';return;}
 }
}
el('connect').onclick=async()=>{
 if(abort)abort.abort();abort=new AbortController();token=el('token').value || token;el('token').value='';
 try{await refresh(abort.signal);el('status').textContent='Connected';stream(abort.signal);}
 catch{el('status').textContent='Authentication or service error';token='';}
};
