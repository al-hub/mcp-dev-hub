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
