import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {runInNewContext} from 'node:vm';

test('stale dashboard login failure cannot clear newer session',async()=>{
 const nodes=Object.fromEntries(['connect','token','jobs','github','status'].map(id=>[id,{value:'',textContent:'',replaceChildren(){}}]));
 const seen=[];
 let rejectOld;
 const pendingOld=new Promise((_,reject)=>{rejectOld=reject;});
 const fetch=(url,options)=>{
  seen.push({url,auth:options.headers.Authorization});
  if(options.headers.Authorization==='Bearer first')return pendingOld;
  if(url==='/api/stream')return new Promise(()=>{});
  return Promise.resolve({ok:true,json:async()=>url==='/api/jobs'?{jobs:[]}:{issues:[],pullRequests:[],ci:[]}});
 };
 const document={getElementById:id=>nodes[id],createElement:()=>({append(){},set textContent(v){},set href(v){},set target(v){},set rel(v){}})};
 runInNewContext(readFileSync(new URL('../src/dashboard/dashboard-client.mjs',import.meta.url),'utf8'),{
  document,fetch,AbortController,TextDecoder,setTimeout:()=>0,setInterval:()=>1,clearInterval:()=>{},Date,Promise
 });
 nodes.token.value='first';
 const first=nodes.connect.onclick();
 nodes.token.value='second';
 await nodes.connect.onclick();
 rejectOld(Error('stale login failed'));
 await first;
 assert.equal(nodes.status.textContent,'Connected');
 nodes.token.value='';
 await nodes.connect.onclick();
 assert.equal(seen.at(-3).auth,'Bearer second');
});
test('SSE event parsing only accepts event lines, not embedded payload substrings',()=>{
 const s=readFileSync(new URL('../src/dashboard/dashboard-client.mjs',import.meta.url),'utf8');
 assert.match(s,/\^event: reset\$/);
 assert.match(s,/\^event: job\$/);
 assert.doesNotMatch(s,/frame\.includes\('event:/);
});


test('invalid replacement preserves current session',async()=>{
 const nodes=Object.fromEntries(['connect','token','jobs','github','status'].map(id=>[id,{value:'',textContent:'',replaceChildren(){}}]));
 const seen=[], streamSignals=[],activeIntervals=new Set();
 const fetch=(url,options)=>{
  seen.push(options.headers.Authorization);
  if(url==='/api/stream'){streamSignals.push(options.signal);return new Promise(()=>{});}
  const accepted=options.headers.Authorization==='Bearer good';
  return Promise.resolve({ok:accepted,status:accepted?200:401,json:async()=>url==='/api/jobs'?{jobs:[]}:{issues:[],pullRequests:[],ci:[]}});
 };
 const document={getElementById:id=>nodes[id],createElement:()=>({append(){},set textContent(v){},set href(v){},set target(v){},set rel(v){}})};
 runInNewContext(readFileSync(new URL('../src/dashboard/dashboard-client.mjs',import.meta.url),'utf8'),{
  document,fetch,AbortController,TextDecoder,setTimeout:()=>0,
  setInterval:()=>{activeIntervals.add(1);return 1;},clearInterval:id=>activeIntervals.delete(id),Date,Promise
 });
 nodes.token.value='good';await nodes.connect.onclick();
 const initialStream=streamSignals[0];
 assert.ok(initialStream&&!initialStream.aborted);
 nodes.token.value='invalid';await nodes.connect.onclick();
 assert.equal(initialStream.aborted,false,'bad candidate must not abort old live stream');
 assert.equal(activeIntervals.size,1,'old refresh timer must remain active');
 nodes.token.value='';await nodes.connect.onclick();
 assert.equal(seen.at(-1),'Bearer good');
 assert.equal(nodes.status.textContent,'Connected');
});
test('aborting SSE reconnect backoff promptly settles and clears timer',async()=>{
 const nodes=Object.fromEntries(['connect','token','jobs','github','status'].map(id=>[id,{value:'',textContent:'',replaceChildren(){}}]));
 const timers=[];
 const context={
  document:{getElementById:id=>nodes[id]},
  fetch:()=>Promise.reject(Error('offline')),
  AbortController,TextDecoder,Date,Promise,
  setTimeout:fn=>{const timer={fn,active:true};timers.push(timer);return timer;},
  clearTimeout:timer=>{timer.active=false;},
  setInterval:()=>1,clearInterval:()=>{}
 };
 runInNewContext(readFileSync(new URL('../src/dashboard/dashboard-client.mjs',import.meta.url),'utf8')+'\nglobalThis.testStream=stream;',context);
 const controller=new AbortController();
 const task=context.testStream(controller.signal);
 await new Promise(resolve=>setImmediate(resolve));
 assert.equal(timers.length,1);
 controller.abort();
 const settled=await Promise.race([task.then(()=>true),new Promise(resolve=>setTimeout(()=>resolve(false),80))]);
 assert.equal(settled,true,'backoff promise must resolve immediately after abort');
 assert.equal(timers[0].active,false,'pending backoff timer must be cleared');
});


test('slow successful login cannot overwrite newer successful session display',async()=>{
 const nodes=Object.fromEntries(['connect','token','jobs','github','status'].map(id=>[id,{value:'',textContent:'',children:[],replaceChildren(...items){this.children=items;}}]));
 let release;
 const pending=new Promise(resolve=>{release=resolve;});
 const response=(url,who)=>({ok:true,json:async()=>url==='/api/jobs'?{jobs:[{kind:who,state:'running',id:'synthetic',updatedAt:'synthetic'}]}:{issues:[],pullRequests:[],ci:[]}});
 const fetch=(url,options)=>{
  if(url==='/api/stream')return new Promise(()=>{});
  return options.headers.Authorization==='Bearer slow'?pending.then(()=>response(url,'slow')):Promise.resolve(response(url,'fast'));
 };
 const createElement=()=>({children:[],append(...items){this.children.push(...items);},set textContent(v){this._textContent=v;},get textContent(){return this._textContent;}});
 runInNewContext(readFileSync(new URL('../src/dashboard/dashboard-client.mjs',import.meta.url),'utf8'),{
  document:{getElementById:id=>nodes[id],createElement},fetch,AbortController,TextDecoder,setTimeout:()=>0,setInterval:()=>1,clearInterval:()=>{},Date,Promise
 });
 nodes.token.value='slow';const first=nodes.connect.onclick();
 nodes.token.value='fast';await nodes.connect.onclick();
 release();await first;
 assert.match(nodes.jobs.children[0].children[0].textContent,/fast/,'stale completed refresh must not overwrite current session');
});

test('empty rapid second Connect click does not invalidate a pending successful login',async()=>{
 const nodes=Object.fromEntries(['connect','token','jobs','github','status'].map(id=>[id,{value:'',textContent:'',replaceChildren(){}}]));
 let release;
 const pending=new Promise(resolve=>{release=resolve;});
 const fetch=(url,options)=>url==='/api/stream'?new Promise(()=>{}):pending.then(()=>({ok:true,json:async()=>url==='/api/jobs'?{jobs:[]}:{issues:[],pullRequests:[],ci:[]}}));
 const document={getElementById:id=>nodes[id],createElement:()=>({append(){}})};
 runInNewContext(readFileSync(new URL('../src/dashboard/dashboard-client.mjs',import.meta.url),'utf8'),{
  document,fetch,AbortController,TextDecoder,setTimeout:()=>0,setInterval:()=>1,clearInterval:()=>{},Date,Promise
 });
 nodes.token.value='good';const first=nodes.connect.onclick();
 await nodes.connect.onclick();
 release();await first;
 assert.equal(nodes.status.textContent,'Connected');
});

test('replacement double click retains pending new session instead of silently reverting to original',async()=>{
 const nodes=Object.fromEntries(['connect','token','jobs','github','status'].map(id=>[id,{value:'',textContent:'',replaceChildren(){}}]));
 const seen=[];
 let release;
 const pending=new Promise(resolve=>{release=resolve;});
 const response=url=>({ok:true,json:async()=>url==='/api/jobs'?{jobs:[]}:{issues:[],pullRequests:[],ci:[]}});
 const fetch=(url,options)=>{
  seen.push({url,auth:options.headers.Authorization});
  if(url==='/api/stream')return new Promise(()=>{});
  return options.headers.Authorization==='Bearer replacement'?pending.then(()=>response(url)):Promise.resolve(response(url));
 };
 runInNewContext(readFileSync(new URL('../src/dashboard/dashboard-client.mjs',import.meta.url),'utf8'),{
  document:{getElementById:id=>nodes[id],createElement:()=>({append(){}})},fetch,AbortController,TextDecoder,Date,Promise,
  setTimeout:()=>0,clearTimeout:()=>{},setInterval:()=>1,clearInterval:()=>{}
 });
 nodes.token.value='original';await nodes.connect.onclick();
 nodes.token.value='replacement';const replacing=nodes.connect.onclick();
 await nodes.connect.onclick();
 release();await replacing;
 assert.equal(seen.filter(x=>x.url==='/api/stream').at(-1).auth,'Bearer replacement');
});

test('old in-flight refresh cannot overwrite replacement session after swap',async()=>{
 const nodes=Object.fromEntries(['connect','token','jobs','github','status'].map(id=>[id,{value:'',textContent:'',children:[],replaceChildren(...items){this.children=items;}}]));
 const deferred=[];let interval;
 const response=req=>({ok:true,json:async()=>req.url==='/api/jobs'?{jobs:[{kind:req.auth,state:'running',id:'synthetic',updatedAt:'synthetic'}]}:{issues:[],pullRequests:[],ci:[]}});
 const fetch=(url,options)=>{
  if(url==='/api/stream')return new Promise(()=>{});
  return new Promise(resolve=>deferred.push({url,auth:options.headers.Authorization,resolve}));
 };
 const createElement=()=>({children:[],append(...items){this.children.push(...items);},set textContent(v){this._textContent=v;},get textContent(){return this._textContent;}});
 runInNewContext(readFileSync(new URL('../src/dashboard/dashboard-client.mjs',import.meta.url),'utf8'),{
  document:{getElementById:id=>nodes[id],createElement},fetch,AbortController,TextDecoder,Date,Promise,
  setTimeout,clearTimeout,setInterval:fn=>{interval=fn;return 1;},clearInterval:()=>{}
 });
 const finish=tasks=>tasks.forEach(t=>t.resolve(response(t)));
 nodes.token.value='original';const initial=nodes.connect.onclick();finish(deferred.splice(0));await initial;
 interval();const old=deferred.splice(0);
 nodes.token.value='replacement';const replacing=nodes.connect.onclick();
 finish(deferred.splice(0));
 await Promise.resolve();
 finish(old);await replacing;
 await new Promise(resolve=>setImmediate(resolve));
 assert.match(nodes.jobs.children[0].children[0].textContent,/replacement/);
});
