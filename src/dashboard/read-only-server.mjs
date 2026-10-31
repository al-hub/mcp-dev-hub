import {timingSafeEqual} from 'node:crypto';
import http from 'node:http';
import {readFileSync} from 'node:fs';
import {publicEvents,eventHistory,eventBounds} from '../../scripts/worker.mjs';

const assets = Object.freeze({'/':['index.html','text/html; charset=utf-8'],'/dashboard-client.mjs':['dashboard-client.mjs','text/javascript; charset=utf-8'],'/dashboard.css':['dashboard.css','text/css; charset=utf-8']});
const isProject = value => typeof value === 'string' && /^[a-z0-9][a-z0-9_-]{1,63}$/.test(value);
export function safeBearer(value,expected) {
  if (typeof expected !== 'string' || expected.length < 24 || typeof value !== 'string' || !value.startsWith('Bearer ')) return false;
  const a=Buffer.from(value.slice(7));const b=Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a,b);
}
export function createReadOnlyDashboard({token,project,repository,db,readGithub,host='localhost',port=0}={}) {
  if (host !== 'localhost') throw Error('dashboard must bind to localhost');
  if (!isProject(project) || typeof token !== 'string' || token.length < 24) throw Error('invalid dashboard configuration');
  if (!repository || !/^[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+$/.test(repository)) throw Error('invalid repository');
  if (typeof readGithub !== 'function' || !db) throw Error('missing read-only dependencies');
  const [owner,repo]=repository.split('/');
  const headers={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Content-Security-Policy':"default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'",'Access-Control-Allow-Origin':'null'};
  const server=http.createServer(async (req,res)=>{
    for(const [key,val] of Object.entries(headers)) if(key!=='Access-Control-Allow-Origin') res.setHeader(key,val);
    try {
    if(req.method==='GET' && Object.hasOwn(assets,req.url)){
      const [filename,type]=assets[req.url];
      res.writeHead(200,{'Content-Type':type});
      res.end(readFileSync(new URL(filename,import.meta.url)));return;
    }
    if (!safeBearer(req.headers.authorization,token)) {res.writeHead(401);res.end('Unauthorized');return;}
    if (req.method!=='GET') {res.writeHead(405);res.end();return;}
      if(req.url==='/api/jobs') {
        res.writeHead(200,{'Content-Type':'application/json'});
        res.end(JSON.stringify({project,jobs:publicEvents(db,project)}));return;
      }
      if(req.url==='/api/stream') {
        const raw=req.headers['last-event-id'];
        if(raw!==undefined && (typeof raw!=='string'|| !/^(0|[1-9][0-9]*)$/.test(raw)||!Number.isSafeInteger(Number(raw)))){res.writeHead(400);res.end('Invalid event cursor');return;}
        res.writeHead(200,{'Content-Type':'text/event-stream; charset=utf-8','Connection':'keep-alive','X-Accel-Buffering':'no'});
        let cursor=raw===undefined?0:Number(raw);
        let active=true;
        let timer;
        const send=()=>{
          if(!active)return;
          try {
            const bounds=eventBounds(db,project);
            if((bounds.last===null && cursor>0) || (bounds.last!==null && cursor>bounds.last)) {
              res.write('event: reset\ndata: {"reason":"cursor-ahead"}\n\n');
              cursor=0;
            }
            // Read in bounded batches, while preserving the last globally unique ID.
            for(let n=0;n<10;n++){
              const rows=eventHistory(db,project,cursor,100);
              for(const e of rows){
                res.write('id: '+e.id+'\nevent: job\ndata: '+JSON.stringify(e)+'\n\n');
                cursor=e.id;
              }
              if(rows.length<100)break;
            }
          }catch {active=false;clearInterval(timer);res.end();}
        };
        timer=setInterval(()=>{send();if(active)res.write(': heartbeat\n\n');},1000);
        req.on('close',()=>{active=false;clearInterval(timer);});
        send();return;
      }
      if(req.url==='/api/github') {
        const snapshot=await readGithub({owner,repo});
        res.writeHead(200,{'Content-Type':'application/json'});
        res.end(JSON.stringify(snapshot));return;
      }
      res.writeHead(404);res.end('Not found');
    } catch {
      if(res.headersSent){res.destroy();}
      else {res.writeHead(503);res.end('Read-only status unavailable');}
    }
  });
  return {server,listen:()=>new Promise((resolve,reject)=>{server.once('error',reject);server.listen(port,host,()=>resolve(server.address()));})};
}
