import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {mkdtempSync,readFileSync,renameSync,rmSync,writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {classifyOwnerPackageTransition as classify}
  from '../src/ops/protected-update-owner-package-transition.mjs';

const previous={head:'a'.repeat(40),packDigest:'1'.repeat(64),
 base:'c'.repeat(40),prNumber:39,ciRunId:101};
const candidate={...previous,head:'b'.repeat(40),
 packDigest:'2'.repeat(64),ciRunId:102};
const pack=({head,packDigest})=>({head,packDigest});
const old={previous,candidate,activePackage:pack(previous),activeTrust:previous,
 backupPackage:null,backupTrust:null,pending:false};
const retained={...old,backupPackage:pack(previous),backupTrust:previous};
const switched={...retained,activePackage:pack(candidate),activeTrust:candidate};

test('intact old state, staged backup, consistent candidate and restored old readback',()=>{
 assert.equal(classify(old).state,'original_consistent');
 assert.equal(classify(retained).state,'original_consistent');
 assert.equal(classify(switched).state,'candidate_consistent');
 assert.equal(classify({...switched,activePackage:pack(previous),
  activeTrust:previous}).state,'original_consistent');
});

test('only complete matching package, trust and backup combinations are consistent',()=>{
 const versions=[previous,candidate,null];
 for(const p of versions)for(const t of versions)
  for(const bp of versions)for(const bt of versions)for(const pending of [false,true,undefined]){
   const verdict=classify({...old,activePackage:p&&pack(p),activeTrust:t,
    backupPackage:bp&&pack(bp),backupTrust:bt,pending});
   const pairedOriginal=bp===previous&&bt===previous;
   const expected=pending!==false?'unknown':
    p===previous&&t===previous&&(pairedOriginal||bp===null&&bt===null)?
     'original_consistent':p===candidate&&t===candidate&&pairedOriginal?
      'candidate_consistent':'unknown';
   assert.equal(verdict.state,expected);
   assert.equal(verdict.requiresReconciliation,expected==='unknown');
   assert.equal(verdict.safeToReplay,false);
   assert.equal(verdict.installAuthorized,false);
   assert.equal(verdict.rollbackAuthorized,false);
  }
});

test('wrong digest, base, PR, CI, malformed or incomplete evidence cannot pass',()=>{
 for(const x of [null,{}, {...switched,backupTrust:undefined},
  {...switched,activeTrust:{...candidate,head:[candidate.head]}},
  {...switched,activeTrust:{...candidate,base:'d'.repeat(40)}},
  {...switched,activeTrust:{...candidate,prNumber:40}},
  {...switched,activeTrust:{...candidate,ciRunId:101}},
  {...switched,activePackage:{...pack(candidate),packDigest:previous.packDigest}},
  {...switched,backupTrust:{...previous,ciRunId:candidate.ciRunId}},
  {...switched,candidate:{...candidate,ciRunId:previous.ciRunId}},
  {...switched,activeTrust:{...candidate,approved:true}}]){
   assert.equal(classify(x).state,'unknown');
 }
});

test('temporary file readback never treats an interrupted switch or restore as complete',t=>{
 const dir=mkdtempSync(join(tmpdir(),'package-transition-'));
 t.after(()=>rmSync(dir,{recursive:true,force:true}));
 const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
 const manifest=head=>JSON.stringify({head});
 const originalBytes=manifest(previous.head),candidateBytes=manifest(candidate.head);
 const a={...previous,packDigest:digest(originalBytes)};
 const b={...candidate,packDigest:digest(candidateBytes)};
 const read=(name,decode=JSON.parse)=>{
  try{return decode(readFileSync(join(dir,name),'utf8'));}
  catch(e){if(e.code==='ENOENT')return null;throw e;}
 };
 const readPack=name=>read(name,raw=>({head:JSON.parse(raw).head,
  packDigest:digest(raw)}));
 const write=(name,raw)=>writeFileSync(join(dir,name),raw);
 const putTrust=(name,trust)=>write(name,JSON.stringify(trust));
 const observe=()=>classify({previous:a,candidate:b,
  activePackage:readPack('active-pack'),activeTrust:read('active-trust'),
  backupPackage:readPack('backup-pack'),backupTrust:read('backup-trust'),
  pending:read('pending')!==null});
 write('active-pack',originalBytes);putTrust('active-trust',a);
 assert.equal(observe().state,'original_consistent');
 write('backup-pack',originalBytes);putTrust('backup-trust',a);
 write('pending','true');write('candidate-pack',candidateBytes);
 renameSync(join(dir,'candidate-pack'),join(dir,'active-pack'));
 assert.equal(observe().state,'unknown');
 putTrust('active-trust',b);
 assert.equal(observe().state,'unknown');
 rmSync(join(dir,'pending'));
 assert.equal(observe().state,'candidate_consistent');
 write('pending','true');putTrust('active-trust',a);
 assert.equal(observe().state,'unknown');
 write('active-pack',originalBytes);
 assert.equal(observe().state,'unknown');
 rmSync(join(dir,'pending'));
 assert.equal(observe().state,'original_consistent');
});
