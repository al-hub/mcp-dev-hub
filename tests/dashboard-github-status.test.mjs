import test from 'node:test';
import assert from 'node:assert/strict';
import { createGithubStatusReader } from '../src/dashboard/github-status.mjs';

test('reads verified GitHub issue, PR and CI state without copying bodies or secrets', async () => {
  const calls=[];
  const responses=[
    [{number:10,title:'Dashboard',state:'open',html_url:'https://github.com/example/app/issues/10',pull_request:null,body:'token=private'}],
    [{number:21,title:'Fix',state:'open',html_url:'https://github.com/example/app/pull/21',merged_at:null,head:{sha:'abc'},body:'secret=private'}],
    [{id:33,name:'CI',status:'completed',conclusion:'success',html_url:'https://github.com/example/app/actions/runs/33'}]
  ];
  const fetchImpl=async(url,opts)=>{calls.push({url,opts});return {ok:true,json:async()=>calls.length===3?{workflow_runs:responses[2]}:responses[calls.length-1]};};
  const read=createGithubStatusReader({fetchImpl,token:'synthetic-token'});
  const result=await read({owner:'example',repo:'app'});
  assert.equal(result.issues[0].state,'open');
  assert.equal(result.pullRequests[0].state,'open');
  assert.equal(result.ci[0].conclusion,'success');
  assert.equal(calls.length,3);
  assert.equal(calls.every(c=>c.opts.headers.Authorization==='Bearer synthetic-token'),true);
  assert.doesNotMatch(JSON.stringify(result),/private|synthetic-token/);
});
test('separates projects and rejects untrusted repository identifiers',async()=>{
 const read=createGithubStatusReader({fetchImpl:async()=>({ok:true,json:async()=>({workflow_runs:[]})})});
 await assert.rejects(()=>read({owner:'example',repo:'../unsafe'}),/invalid repository/);
});
test('fails closed when upstream GitHub request fails',async()=>{
 const read=createGithubStatusReader({fetchImpl:async()=>({ok:false,status:403})});
 await assert.rejects(()=>read({owner:'example',repo:'app'}),/GitHub status unavailable/);
});
