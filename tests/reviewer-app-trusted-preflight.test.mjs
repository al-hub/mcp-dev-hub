import test from 'node:test';
import assert from 'node:assert/strict';
import {parseTrustedAppConfiguration,checkTrustedAppConnection}
 from '../scripts/reviewer-app-trusted-preflight.mjs';
const sha='a'.repeat(40);
const config={appId:5576601,expectedHead:sha,
 keyFile:'/etc/mcp-dev-hub/reviewer-app.pem'};
const canonical=JSON.stringify(config);
const nested={...config,keyFile:'/etc/mcp-dev-hub/reviewer/reviewer-app.pem'};
test('only fixed root credential leaf and exact SHA are allowed',()=>{
 assert.deepEqual(parseTrustedAppConfiguration(canonical),config);
 assert.deepEqual(parseTrustedAppConfiguration(JSON.stringify(nested)),nested);
 for(const bad of [
  {...config,keyFile:'/tmp/reviewer-app.pem'},
  {...config,keyFile:'/etc/mcp-dev-hub/../bad.pem'},
  {...config,keyFile:'/etc/mcp-dev-hub/nested/deeper/key.pem'},
  {...config,keyFile:'/etc/mcp-dev-hub/nested/../key.pem'},
  {...config,keyFile:'/etc/mcp-dev-hub/nested//key.pem'},
  {...config,keyFile:'/etc/mcp-dev-hub/.hidden/key.pem'},
  {...config,expectedHead:'bad'},
  {...config,appId:0},
  {...config,appId:42},
  {...config,appId:5576602},
  {...config,unexpected:true}
 ])assert.throws(()=>parseTrustedAppConfiguration(JSON.stringify(bad)));
 assert.throws(()=>parseTrustedAppConfiguration(canonical+'\n{}'));
});
test('checkout execution never authenticates, even with injected client',async()=>{
 let called=false;
 const r=await checkTrustedAppConnection({config,
  readKey:()=>{called=true;return 'synthetic';},
  createClient:async()=>{throw Error('should not reach client');}});
 assert.equal(r.status,'blocked');
 assert.equal(called,false);
});
test('missing real root-owned config or key cannot report ready',async()=>{
 for(const c of [{...config,keyFile:'/etc/mcp-dev-hub/nope.pem'},
                 {...config,expectedHead:'invalid'}]){
  const r=await checkTrustedAppConnection({config:c});
  assert.equal(r.status,'blocked');
 }
});

test('the trusted preflight only authenticates the fixed App and reads PR39',async()=>{
 const calls=[],key='synthetic-RSA-private-key';
 const result=await checkTrustedAppConnection({config,
  readOwnedFile:(path,mode,max)=>{
   assert.equal(path,config.keyFile);assert.equal(mode,0o600);
   assert.equal(max,16384);return key;
  },
  readKey:path=>{assert.equal(path,config.keyFile);return key;},
  installationLookup:async o=>{
   assert.equal(o.appId,5576601);assert.equal(o.key,key);return 123;
  },
  createClient:async o=>{
   assert.equal(o.appId,5576601);assert.equal(o.installationId,123);
   assert.equal(o.prNumber,39);assert.equal(o.repositoryId,1440361577);
   return {actor:'mcp-dev-hub-ai-reviewer[bot]',api:async(method,path)=>{
    calls.push([method,path]);
    return {number:39,state:'open',draft:false,head:{sha},
     base:{ref:'main',repo:{full_name:'al-hub/mcp-dev-hub'}},
     user:{login:'al-hub'}};
   }};
  }
 });
 assert.equal(result.status,'ready');
 assert.equal(result.approvalSubmitted,false);
 assert.deepEqual(calls,[['GET','/repos/al-hub/mcp-dev-hub/pulls/39']]);
});
test('wrong Bot, moved SHA or app authentication failure never emits ready',async()=>{
 const shared={config,
  readOwnedFile:()=> 'synthetic',readKey:()=> 'synthetic',
  installationLookup:async()=>123};
 for(const bad of ['wrong-bot','stale-head','no-app-token']){
  const result=await checkTrustedAppConnection({...shared,
   createClient:async()=>{
    if(bad==='no-app-token')throw Error('transport failure');
    return {actor:bad==='wrong-bot'?'evil[bot]':
       'mcp-dev-hub-ai-reviewer[bot]',
     api:async()=>({number:39,state:'open',draft:false,
      head:{sha:bad==='stale-head'?'b'.repeat(40):sha},
      base:{ref:'main',repo:{full_name:'al-hub/mcp-dev-hub'}},
      user:{login:'al-hub'}})};
   }
  });
  assert.equal(result.status,'blocked');
 }
});

test('installed one-level nested key parent must be private before any read',async()=>{
 let parentChecked=0,read=false;
 const result=await checkTrustedAppConnection({
  config:nested,validatePrivateDirectory:(path,privateDir)=>{
   parentChecked++;
   assert.equal(path,'/etc/mcp-dev-hub/reviewer');
   assert.equal(privateDir,true);
   throw Error('mock insecure ancestor');
  },
  readOwnedFile:()=>{read=true;return 'must never happen';}
 });
 assert.equal(result.status,'blocked');
 assert.equal(parentChecked,1);
 assert.equal(read,false);
});
test('same nested private key works with explicitly verified parent',async()=>{
 const key='synthetic-only',calls=[];
 const result=await checkTrustedAppConnection({
  config:nested,
  validatePrivateDirectory:(path,privateDir)=>{
   calls.push(['parent',path,privateDir]);
  },
  readOwnedFile:(path,mode)=>{calls.push(['key',path,mode]);return key;},
  readKey:()=>key,
  installationLookup:async()=>123,
  createClient:async()=>({actor:'mcp-dev-hub-ai-reviewer[bot]',
   api:async()=>({number:39,state:'open',draft:false,
    head:{sha},base:{ref:'main',repo:{full_name:'al-hub/mcp-dev-hub'}},
    user:{login:'al-hub'}})})
 });
 assert.equal(result.status,'ready');
 assert.deepEqual(calls,[
  ['parent','/etc/mcp-dev-hub/reviewer',true],
  ['key','/etc/mcp-dev-hub/reviewer/reviewer-app.pem',0o600]
 ]);
});
