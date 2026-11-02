import test from 'node:test';
import assert from 'node:assert/strict';
import {DatabaseSync} from 'node:sqlite';
import http from 'node:http';
import {createReadOnlyDashboard} from '../src/dashboard/read-only-server.mjs';

test('read-only HTTP only accepts same-origin loopback requests', async () => {
  const db=new DatabaseSync(':memory:');
  db.exec('CREATE TABLE jobs (id TEXT,kind TEXT,project TEXT,state TEXT,exit_code INTEGER,created_at TEXT,updated_at TEXT)');
  const app=createReadOnlyDashboard({
    token:'synthetic-origin-test-token-123456',
    project:'demo', repository:'example/app', db,
    readGithub:async()=>({issues:[],pullRequests:[],ci:[]})
  });
  try {
    const address=await app.listen();
    const origin='http://localhost:'+address.port;
    const headers={Authorization:'Bearer synthetic-origin-test-token-123456'};
    for(const route of ['/api/jobs','/api/github','/api/stream']) {
      const bad=await fetch(origin+route,{headers:{...headers,Origin:'https://untrusted.invalid'}});
      assert.equal(bad.status,403,route+' must reject untrusted Origin');
      await bad.body?.cancel();
    }
    const nullOrigin=await fetch(origin+'/api/jobs',{headers:{...headers,Origin:'null'}});
    assert.equal(nullOrigin.status,403);
    const otherPort=await fetch(origin+'/api/jobs',{headers:{...headers,Origin:'http://localhost:9999'}});
    assert.equal(otherPort.status,403);
    const hostileHostStatus=await new Promise((resolve,reject)=>{
      http.get(origin+'/api/jobs',{headers:{...headers,Host:'untrusted.invalid'}},res=>{
        res.resume();resolve(res.statusCode);
      }).on('error',reject);
    });
    assert.equal(hostileHostStatus,403);
    const allowed=await fetch(origin+'/api/jobs',{headers:{...headers,Origin:origin}});
    assert.equal(allowed.status,200);
    const noOrigin=await fetch(origin+'/api/jobs',{headers});
    assert.equal(noOrigin.status,200);
  } finally {
    await new Promise(resolve=>app.server.close(resolve));
    db.close();
  }
});
