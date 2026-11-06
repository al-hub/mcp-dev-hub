import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {
  chmodSync,lstatSync,mkdirSync,mkdtempSync,readdirSync,rmSync
} from 'node:fs';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {APPROVAL_DOMAIN} from '../src/ops/protected-update-approval.mjs';
import {
  RELEASE_FILES,inspectProtectedRelease,stageProtectedRelease,
  switchProtectedRelease
} from '../src/ops/protected-update-release-pointer.mjs';
import {
  readStoredProtectedUpdateJournal
} from '../src/ops/protected-update-journal-store.mjs';
import {
  preflightProtectedUpdate,applyProtectedUpdateCandidate
} from '../src/ops/protected-update-transaction.mjs';
const A='a'.repeat(40),B='b'.repeat(40),C='c'.repeat(40);
const ID1='1'.repeat(32),ID2='2'.repeat(32),now=1793900000000;
const pair=generateKeyPairSync('ed25519');
const publicKey=pair.publicKey.export({type:'spki',format:'pem'});
const sha=buf=>createHash('sha256').update(buf).digest('hex');
const content=word=>Object.fromEntries(RELEASE_FILES.map((name,i)=>[
  name,Buffer.from('synthetic-'+word+'-'+i+'\n')
]));
const meta=data=>RELEASE_FILES.map(name=>({
  name,bytes:data[name].length,sha256:sha(data[name])
}));
function dirs(t){
  const root=mkdtempSync(join(tmpdir(),'protected-txn-root-'));
  mkdirSync(join(root,'versions'),{mode:0o755});
  chmodSync(root,0o755);
  chmodSync(join(root,'versions'),0o755);
  const stateDir=mkdtempSync(join(tmpdir(),'protected-txn-state-'));
  t.after(()=>{
    for(const name of readdirSync(join(root,'versions'))){
      const dir=join(root,'versions',name);
      if(lstatSync(dir).isDirectory())chmodSync(dir,0o700);
    }
    rmSync(root,{recursive:true,force:true});
    rmSync(stateDir,{recursive:true,force:true});
  });
  const old=content('A'),oldFiles=meta(old);
  stageProtectedRelease(root,{commit:A,files:oldFiles,contents:old});
  switchProtectedRelease(root,{expectedCommit:null,nextCommit:A,nextFiles:oldFiles});
  return {root,stateDir,oldFiles};
}
function request({head=B,base=A,id=ID1,word='B'}={}){
  const contents=content(word);
  const files=meta(contents);
  const manifestJson=JSON.stringify({
    version:1,repository:'al-hub/mcp-dev-hub',commit:head,
    bundle:'controller-pair',files
  });
  const reviewDigest='d'.repeat(64);
  const ciRunId=42200000000;
  const approvalJson=JSON.stringify({
    version:1,repository:'al-hub/mcp-dev-hub',scope:'controller-pair',
    head,base,manifestSha256:sha(Buffer.from(manifestJson)),ciRunId,
    ciHead:head,reviewHead:head,reviewBase:base,reviewDigest,
    reviewVerdict:'PASS',operationId:id,
    issuedAtMs:now-1000,expiresAtMs:now+50000
  });
  const signatureBase64=sign(null,Buffer.from(APPROVAL_DOMAIN+approvalJson),
    pair.privateKey).toString('base64');
  const proof=Object.freeze({
    base,ciHead:head,ciPassed:true,ciRunId,head,
    independentReviewPassed:true,reviewBase:base,reviewDigest,
    reviewHead:head,strictProtection:true
  });
  return {
    manifestJson,approvalJson,signatureBase64,
    pinnedPublicKey:publicKey,proof,operationId:id,nowMs:now,contents,files
  };
}
test('authenticated synthetic two serial updates use journal + atomic CAS',async t=>{
  const env=dirs(t);
  const first=request();
  const result1=await applyProtectedUpdateCandidate({
    ...env,...first,observeHealth:async()=>true
  });
  assert.equal(result1.phase,'verified');
  assert.equal(inspectProtectedRelease(env.root,{files:first.files}),B);
  assert.equal(readStoredProtectedUpdateJournal(env.stateDir,ID1).phase,
    'verified');
  const second=request({head:C,base:B,id:ID2,word:'C'});
  const result2=await applyProtectedUpdateCandidate({
    root:env.root,stateDir:env.stateDir,
    ...second,oldFiles:first.files,observeHealth:async()=>true
  });
  assert.equal(result2.phase,'verified');
  assert.equal(inspectProtectedRelease(env.root,{files:second.files}),C);
  assert.equal(readStoredProtectedUpdateJournal(env.stateDir,ID2).phase,
    'verified');
});
test('failed health results in CAS rollback and terminal evidence',async t=>{
  const env=dirs(t),req=request();
  const result=await applyProtectedUpdateCandidate({
    ...env,...req,observeHealth:async()=>false
  });
  assert.equal(result.phase,'rolled_back');
  assert.equal(inspectProtectedRelease(env.root,{files:env.oldFiles}),A);
  assert.equal(readStoredProtectedUpdateJournal(env.stateDir,ID1).phase,
    'rolled_back');
});
test('uncertain health retains switched journal; no unknown replay',async t=>{
  const env=dirs(t),req=request();
  await assert.rejects(applyProtectedUpdateCandidate({
    ...env,...req,observeHealth:async()=>{throw Error('transport_unknown');}
  }),/transport_unknown/);
  assert.equal(inspectProtectedRelease(env.root,{files:req.files}),B);
  assert.equal(readStoredProtectedUpdateJournal(env.stateDir,ID1).phase,
    'switched');
  const next=request({head:C,base:B,id:ID2,word:'C'});
  await assert.rejects(applyProtectedUpdateCandidate({
    root:env.root,stateDir:env.stateDir,...next,
    oldFiles:req.files,observeHealth:async()=>true
  }),/protected_journal_store_guard_failed/);
});
test('tampered approval and untrusted or missing GitHub proof fail before any stage',async t=>{
  const env=dirs(t),req=request();
  for(const mutation of [
    {signatureBase64:req.signatureBase64.slice(0,84)+'AAAA'},
    {proof:Object.freeze({...req.proof,ciPassed:false})},
    {proof:Object.freeze({...req.proof,strictProtection:false})},
    {proof:Object.freeze({...req.proof,independentReviewPassed:false})},
    {proof:Object.freeze({...req.proof,ciRunId:1})},
    {proof:{...req.proof}}
  ]){
    await assert.rejects(applyProtectedUpdateCandidate({
      ...env,...req,...mutation,observeHealth:async()=>true
    }));
    assert.equal(inspectProtectedRelease(env.root,{files:env.oldFiles}),A);
    assert.equal(readStoredProtectedUpdateJournal(env.stateDir,ID1),null);
  }
});
test('isolated preflight requires pinned trusted key and immutable evidence',()=>{
  const req=request();
  assert.equal(preflightProtectedUpdate(req).head,B);
  assert.throws(()=>preflightProtectedUpdate({
    ...req, pinnedPublicKey:generateKeyPairSync('ed25519')
      .publicKey.export({type:'spki',format:'pem'})
  }));
});

test('subsequent authenticated update may reuse exact rolled-back release',async t=>{
  const env=dirs(t),first=request();
  const rolled=await applyProtectedUpdateCandidate({
    ...env,...first,observeHealth:async()=>false
  });
  assert.equal(rolled.phase,'rolled_back');
  assert.equal(inspectProtectedRelease(env.root,{files:env.oldFiles}),A);
  const second=request({head:B,base:A,id:ID2,word:'B'});
  const result=await applyProtectedUpdateCandidate({
    ...env,...second,observeHealth:async()=>true
  });
  assert.equal(result.phase,'verified');
  assert.equal(inspectProtectedRelease(env.root,{files:second.files}),B);
  assert.equal(readStoredProtectedUpdateJournal(env.stateDir,ID1).phase,
    'rolled_back');
  assert.equal(readStoredProtectedUpdateJournal(env.stateDir,ID2).phase,
    'verified');
});
test('corrupt existing release denies next operation before journal write',async t=>{
  const env=dirs(t),first=request();
  await applyProtectedUpdateCandidate({
    ...env,...first,observeHealth:async()=>false
  });
  const tampered=join(env.root,'versions',B);
  chmodSync(tampered,0o700);
  const second=request({head:B,base:A,id:ID2,word:'B'});
  await assert.rejects(applyProtectedUpdateCandidate({
    ...env,...second,observeHealth:async()=>true
  }),/protected_release_guard_failed/);
  assert.equal(readStoredProtectedUpdateJournal(env.stateDir,ID2),null);
  assert.equal(inspectProtectedRelease(env.root,{files:env.oldFiles}),A);
});
