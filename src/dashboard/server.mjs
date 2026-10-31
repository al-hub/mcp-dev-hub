import http from 'node:http';
import {timingSafeEqual} from 'node:crypto';
import {EventStore} from './events.mjs';
const store=new EventStore();
const token=process.env.DASHBOARD_TOKEN;
const project=process.env.DASHBOARD_PROJECT||'demo';
const port=Number(process.env.DASHBOARD_PORT||8765);
const host=process.env.DASHBOARD_HOST||'127.0.0.1';
if(!token||token.length<24)throw Error('DASHBOARD_TOKEN must be configured (24+ characters)');
function authorized(req){
  const value=req.headers.authorization||'';
  const supplied=value.startsWith('Bearer ')?value.slice(7):'';
  const a=Buffer.from(supplied),b=Buffer.from(token);
  return a.length===b.length&&timingSafeEqual(a,b);
}
const html=`<!doctype html><html lang="ko"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>MCP Dev Hub</title><style>body{font:16px system-ui;background:#101725;color:#e9edf7;margin:auto;max-width:900px;padding:24px}header{display:flex;justify-content:space-between;align-items:center}article{background:#202c40;border-radius:12px;padding:16px;margin:12px 0}small{color:#aab9ce}pre{white-space:pre-wrap;overflow-wrap:anywhere}input,button{padding:10px;border-radius:6px}</style><header><h2>MCP Dev Hub</h2><small>Read-only</small></header><article><label>Access token <input id="token" type="password" autocomplete="off"></label> <button id="connect">Connect</button><p id="status">Not connected</p></article><section id="events"></section><script>const el=document.getElementById('events');document.getElementById('connect').onclick=async()=>{const token=document.getElementById('token').value;const r=await fetch('/api/events',{headers:{Authorization:'Bearer '+token}});document.getElementById('status').textContent=r.ok?'Connected (polling every 2s)':'Unauthorized';if(!r.ok)return;const draw=async()=>{const r=await fetch('/api/events',{headers:{Authorization:'Bearer '+token}});if(!r.ok)return;const a=await r.json();el.replaceChildren(...a.slice().reverse().map(e=>{const x=document.createElement('article');const h=document.createElement('strong');h.textContent=e.cli+' — '+e.state;const p=document.createElement('pre');p.textContent=e.message;const s=document.createElement('small');s.textContent=e.at+' · '+e.source;x.append(h,s,p);return x;}));};await draw();setInterval(draw,2000);};</script></html>`;
const server=http.createServer((req,res)=>{
  res.setHeader('Cache-Control','no-store');
  res.setHeader('X-Content-Type-Options','nosniff');
  res.setHeader('Content-Security-Policy',"default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'");
  if(req.url==='/'&&req.method==='GET'){res.writeHead(200,{'Content-Type':'text/html; charset=utf-8'});return res.end(html);}
  if(!authorized(req)){res.writeHead(401);return res.end('Unauthorized');}
  if(req.url==='/api/events'&&req.method==='GET'){res.writeHead(200,{'Content-Type':'application/json'});return res.end(JSON.stringify(store.list(project)));}
  if(req.url?.startsWith('/api/stream')&&req.method==='GET'){
    res.writeHead(200,{'Content-Type':'text/event-stream','Connection':'keep-alive'});
    const since=Number(req.headers['last-event-id']||0);
    for(const e of store.list(project,Number.isSafeInteger(since)&&since>=0?since:0))res.write('id: '+e.id+'\ndata: '+JSON.stringify(e)+'\n\n');
    const unsub=store.subscribe(e=>{if(e.project===project)res.write('id: '+e.id+'\ndata: '+JSON.stringify(e)+'\n\n');});
    const keep=setInterval(()=>res.write(': heartbeat\n\n'),15000);
    req.on('close',()=>{clearInterval(keep);unsub();});return;
  }
  res.writeHead(404);res.end('Not found');
});
server.listen(port,host,()=>console.error('dashboard listening on configured private interface'));
