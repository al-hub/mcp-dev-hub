import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,mkdirSync,chmodSync,readdirSync,readFileSync,rmSync,symlinkSync} from 'node:fs';
import {readStoredProtectedUpdateHistory}
 from '../src/ops/protected-update-journal-store.mjs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fenceApprovalPost} from '../src/jobs/github-app-publication-fence.mjs';
const head='a'.repeat(40),base='b'.repeat(40);
const evidenceId='verified-synthetic-codex-proof';
const path='/repos/al-hub/mcp-dev-hub/pulls/39/reviews';
const body={commit_id:head,event:'APPROVE',
 body:'AI-assisted independent Codex technical review (not a human review). Evidence: '+evidenceId};
function fixture(fn){
 const directory=mkdtempSync(join(tmpdir(),'app-fence-'));chmodSync(directory,0o700);
 const args={api:fn,directory,head,base,evidenceId,owner:process.getuid()};
 return {directory,args,clean:()=>rmSync(directory,{recursive:true,force:true})};
}
test('intent is durable before POST; successful response stays separately recorded',async()=>{
 let calls=0;
 const f=fixture(async()=>{
  calls++;
  const files=readdirSync(f.directory);
  assert.equal(files.length,1);
  const intent=JSON.parse(readFileSync(join(f.directory,files[0]),'utf8'));
  assert.equal(intent.state,'dispatched_or_unknown');
  return {id:23};
 });
 try{
  const api=fenceApprovalPost(f.args);
  assert.equal((await api('POST',path,body)).id,23);
  assert.equal(readdirSync(f.directory).length,2);
  await assert.rejects(api('POST',path,body));
  assert.equal(calls,1);
 }finally{f.clean();}
});
test('unknown POST survives new invocation and changed evidence without retransmission',async()=>{
 let posts=0;
 const f=fixture(async(method)=>{if(method==='POST'){posts++;throw Error('disconnect');}return [];});
 try{
  await assert.rejects(fenceApprovalPost(f.args)('POST',path,body));
  const next=fenceApprovalPost(f.args);
  assert.deepEqual(await next('GET',path+'?per_page=100'),[]);
  await assert.rejects(next('POST',path,body));
  const changed='verified-other-codex-proof';
  await assert.rejects(fenceApprovalPost({...f.args,evidenceId:changed})('POST',path,
   {...body,body:body.body.replace(evidenceId,changed)}));
  assert.equal(posts,1);
 }finally{f.clean();}
});
test('concurrent publishers dispatch at most once',async()=>{
 let posts=0;const f=fixture(async()=>{posts++;return {id:24};});
 try{
  const results=await Promise.allSettled([
   fenceApprovalPost(f.args)('POST',path,body),
   fenceApprovalPost(f.args)('POST',path,body)
  ]);
  assert.equal(results.filter(r=>r.status==='fulfilled').length,1);
  assert.equal(posts,1);
 }finally{f.clean();}
});
test('untrusted directory and altered request denied before network',async()=>{
 let posts=0;const f=fixture(async()=>{posts++;return {id:25};});
 try{
  const api=fenceApprovalPost(f.args);
  for(const altered of [{...body,event:'COMMENT'},{...body,commit_id:base},
    {...body,body:'fake proof'},{...body,extra:true}])
   await assert.rejects(api('POST',path,altered));
  chmodSync(f.directory,0o755);
  assert.throws(()=>fenceApprovalPost(f.args));
  assert.equal(posts,0);
 }finally{f.clean();}
});
test('failed or malformed POST response remains permanently fenced',async()=>{
 let posts=0;const f=fixture(async()=>{posts++;return {};});
 try{
  await assert.rejects(fenceApprovalPost(f.args)('POST',path,body));
  await assert.rejects(fenceApprovalPost(f.args)('POST',path,body));
  assert.equal(posts,1);
 }finally{f.clean();}
});

test('expired signature precheck rejects before consuming any POST fence',async()=>{
 let posts=0;const f=fixture(async()=>{posts++;return {id:42};});
 try{
  let valid=false;
  const rejected=fenceApprovalPost({...f.args,
   validateBeforePost:()=>{if(!valid)throw Error('signed packet expired');}
  });
  await assert.rejects(rejected('POST',path,body),/expired/);
  assert.deepEqual(readdirSync(f.directory),[]);
  valid=true;
  const sent=await rejected('POST',path,body);
  assert.equal(sent.id,42);assert.equal(posts,1);
  assert.equal(readdirSync(f.directory).length,2);
  await assert.rejects(rejected('POST',path,body));
  assert.equal(posts,1);
 }finally{f.clean();}
});
test('asynchronous precheck cannot cross the non-replayable fence',async()=>{
 let posts=0;const f=fixture(async()=>{posts++;return {id:43};});
 try{
  const api=fenceApprovalPost({...f.args,
    validateBeforePost:()=>Promise.resolve(true)});
  await assert.rejects(api('POST',path,body));
  assert.equal(readdirSync(f.directory).length,0);
  assert.equal(posts,0);
 }finally{f.clean();}
});

test('pre-bootstrap App POST fence cannot poison the separately activated update journal',async()=>{
 const tmp=mkdtempSync(join(tmpdir(),'mcp35-two-ledgers-'));
 const publisher=join(tmp,'app-publication');
 const journal=join(tmp,'protected-update');
 try{
  mkdirSync(publisher,{mode:0o700});
  let posts=0;
  const api=fenceApprovalPost({
   api:async()=>{posts++;return {id:51}},
   directory:publisher,head,base,evidenceId,owner:process.getuid()
  });
  assert.equal((await api('POST',path,body)).id,51);
  assert.equal(posts,1);
  mkdirSync(journal,{mode:0o700});
  assert.deepEqual(readStoredProtectedUpdateHistory(journal),[]);
  assert.equal(readdirSync(publisher).length,2);
  const published=readFileSync(new URL('../scripts/reviewer-app-trusted-publish.mjs',import.meta.url),'utf8');
  const provision=readFileSync(new URL('../scripts/protected-update-issuer-provision.mjs',import.meta.url),'utf8');
  const activated=readFileSync(new URL('../scripts/protected-update-os-activate.mjs',import.meta.url),'utf8');
  assert.ok(published.includes("const STATE='/var/lib/mcp-dev-hub-signers/app-publication';"));
  assert.ok(provision.includes('mkdirSync(APP_PUBLICATION,{mode:0o700})'));
  // publisher must not require later-created journal parent for App POST
  const ancestors=published.slice(published.indexOf('for(const p of ['),published.indexOf('trustedDirectory(STATE,true)'));
  assert.ok(!ancestors.includes("'/var/lib/mcp-dev-hub'"));
  assert.ok(activated.includes("const STATE='/var/lib/mcp-dev-hub/protected-update';"));
 }finally{rmSync(tmp,{recursive:true,force:true});}
});
