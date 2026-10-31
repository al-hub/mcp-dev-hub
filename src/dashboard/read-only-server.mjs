import {timingSafeEqual,createHash} from 'node:crypto';
import http from 'node:http';
import {readFileSync} from 'node:fs';
import {publicEvents,eventHistory,eventBounds} from '../../scripts/worker.mjs';

const assets = Object.freeze(Object.fromEntries(Object.entries({'/':['index.html','text/html; charset=utf-8'],'/dashboard-client.mjs':['dashboard-client.mjs','text/javascript; charset=utf-8'],'/dashboard.css':['dashboard.css','text/css; charset=utf-8']}).map(([route,[file,type]])=>[route,{type,body:readFileSync(new URL(file,import.meta.url))}])));
const isProject = value => typeof value === 'string' && /^[a-z0-9][a-z0-9_-]{1,63}$/.test(value);
export function safeBearer(value,expected) {
  if (typeof expected !== 'string' || expected.length < 24 || typeof value !== 'string' || !value.startsWith('Bearer ')) return false;
  const a=createHash('sha256').update(value.slice(7)).digest();const b=createHash('sha256').update(expected).digest();
  return timingSafeEqual(a,b);
}
export function createReadOnlyDashboard({token,project,repository,db,readGithub,host='localhost',port=0}={}) {
  if (host !== 'localhost') throw Error('dashboard must bind to localhost');
  if (!isProject(project) || typeof token !== 'string' || token.length < 24) throw Error('invalid dashboard configuration');
  if (!repository || !/^[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+$/.test(repository)) throw Error('invalid repository');
  if (typeof readGithub !== 'function' || !db) throw Error('missing read-only dependencies');
  const [owner,repo]=repository.split('/');
  let activeStreams=0;
  let githubCache=null,githubCacheAt=0,githubPending=null;
  const cachedGithub=async()=>{
    if(githubCache && Date.now()-githubCacheAt<30000)return githubCache;
    if(!githubPending)githubPending=Promise.resolve().then(()=>readGithub({owner,repo})).then(data=>{githubCache=data;githubCacheAt=Date.now();return data;}).finally(()=>{githubPending=null;});
    return githubPending;
  };
  const headers={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Content-Security-Policy':"default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'",'Access-Control-Allow-Origin':'null'};
  const server=http.createServer(async (req,res)=>{
    for(const [key,val] of Object.entries(headers)) if(key!=='Access-Control-Allow-Origin') res.setHeader(key,val);
    try {
    if(req.method==='GET' && Object.hasOwn(assets,req.url)){
      const {type,body}=assets[req.url];
      res.writeHead(200,{'Content-Type':type});
      res.end(body);return;
    }
    if (!safeBearer(req.headers.authorization,token)) {res.writeHead(401);res.end('Unauthorized');return;}
    if (req.method!=='GET') {res.writeHead(405);res.end();return;}
      if(req.url==='/api/jobs') {
        const body=JSON.stringify({project,jobs:publicEvents(db,project)});
        res.writeHead(200,{'Content-Type':'application/json'});
        res.end(body);return;
      }
      if(req.url==='/api/stream') {
        if(activeStreams>=8){res.writeHead(429);res.end('Too many streams');return;}
        const raw=req.headers['last-event-id'];
        if(raw!==undefined && (typeof raw!=='string'|| !/^(0|[1-9][0-9]*)$/.test(raw)||!Number.isSafeInteger(Number(raw)))){res.writeHead(400);res.end('Invalid event cursor');return;}
        activeStreams++;
        res.writeHead(200,{'Content-Type':'text/event-stream; charset=utf-8','Connection':'keep-alive','X-Accel-Buffering':'no'});
        let cursor=raw===undefined?0:Number(raw);
        let active=true;
        let timer;
        const safeWrite=chunk=>{if(!active||res.destroyed)return false;if(res.writableLength>262144){active=false;clearInterval(timer);res.destroy();return false;}return res.write(chunk);};
        const send=()=>{
          if(!active)return;
          try {
            const bounds=eventBounds(db,project);
            if((bounds.last===null && cursor>0) || (bounds.last!==null && cursor>bounds.last)) {
              if(!safeWrite('event: reset\ndata: {"reason":"cursor-ahead"}\n\n'))return;
              cursor=0;
            }
            // Read in bounded batches, while preserving the last globally unique ID.
            for(let n=0;n<10;n++){
              const rows=eventHistory(db,project,cursor,100);
              for(const e of rows){
                const sent=safeWrite('id: '+e.id+'\nevent: job\ndata: '+JSON.stringify(e)+'\n\n');
                cursor=e.id;
                if(!sent)return;
              }
              if(rows.length<100)break;
            }
          }catch {active=false;clearInterval(timer);res.end();}
        };
        timer=setInterval(()=>{send();if(active)try{safeWrite(': heartbeat\n\n');}catch{active=false;clearInterval(timer);res.destroy();}},1000);
        req.on('close',()=>{if(activeStreams>0)activeStreams--;active=false;clearInterval(timer);});
        send();return;
      }
      if(req.url==='/api/github') {
        const snapshot=await cachedGithub();
        const body=JSON.stringify(snapshot);
        res.writeHead(200,{'Content-Type':'application/json'});
        res.end(body);return;
      }
      res.writeHead(404);res.end('Not found');
    } catch {
      if(res.headersSent){res.destroy();}
      else {res.writeHead(503);res.end('Read-only status unavailable');}
    }
  });
  server.requestTimeout=15000;
  server.headersTimeout=10000;
  return {server,listen:()=>new Promise((resolve,reject)=>{server.once('error',reject);server.listen(port,host,()=>resolve(server.address()));})};
}
