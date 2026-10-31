import {timingSafeEqual} from 'node:crypto';
import http from 'node:http';
import {publicEvents} from '../../scripts/worker.mjs';

const isProject = value => typeof value === 'string' && /^[a-z0-9][a-z0-9_-]{1,63}$/.test(value);
export function safeBearer(value,expected) {
  if (typeof expected !== 'string' || expected.length < 24 || typeof value !== 'string' || !value.startsWith('Bearer ')) return false;
  const a=Buffer.from(value.slice(7));const b=Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a,b);
}
export function createReadOnlyDashboard({token,project,repository,db,readGithub,host='127.0.0.1',port=0}={}) {
  if (!isProject(project) || typeof token !== 'string' || token.length < 24) throw Error('invalid dashboard configuration');
  if (!repository || !/^[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+$/.test(repository)) throw Error('invalid repository');
  if (typeof readGithub !== 'function' || !db) throw Error('missing read-only dependencies');
  const [owner,repo]=repository.split('/');
  const headers={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Content-Security-Policy':"default-src 'none'",'Access-Control-Allow-Origin':'null'};
  const server=http.createServer(async (req,res)=>{
    for(const [key,val] of Object.entries(headers)) if(key!=='Access-Control-Allow-Origin') res.setHeader(key,val);
    if (!safeBearer(req.headers.authorization,token)) {res.writeHead(401);res.end('Unauthorized');return;}
    if (req.method!=='GET') {res.writeHead(405);res.end();return;}
    try {
      if(req.url==='/api/jobs') {
        res.writeHead(200,{'Content-Type':'application/json'});
        res.end(JSON.stringify({project,jobs:publicEvents(db,project)}));return;
      }
      if(req.url==='/api/github') {
        const snapshot=await readGithub({owner,repo});
        res.writeHead(200,{'Content-Type':'application/json'});
        res.end(JSON.stringify(snapshot));return;
      }
      res.writeHead(404);res.end('Not found');
    } catch {
      res.writeHead(503);res.end('Read-only status unavailable');
    }
  });
  return {server,listen:()=>new Promise((resolve,reject)=>{server.once('error',reject);server.listen(port,host,()=>resolve(server.address()));})};
}
