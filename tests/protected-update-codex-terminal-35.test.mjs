import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {readFileSync} from 'node:fs';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {
  validatePersistedCodexPass,makeCodexReceiptClaim,
  makePinnedCodexReviewInput,validatePinnedCodexSourceReviewInput
} from '../src/ops/protected-update-codex-terminal.mjs';
import {INDEPENDENT_REVIEW_DOMAIN,INDEPENDENT_REVIEW_DOMAIN_V2,
  verifyIndependentSignedReview}
  from '../src/ops/protected-update-github-evidence.mjs';
import {PROTECTED_BOOTSTRAP_FILES}
  from '../scripts/protected-update-bootstrap-pack.mjs';
import {supportedProtectedExecutableSize}
  from '../scripts/protected-update-codex-receipt.mjs';

const HEAD='a'.repeat(40),BASE='b'.repeat(40);
const RUN='c'.repeat(32),NOW=Date.parse('2026-11-08T02:00:00Z');
const raw=JSON.stringify({verdict:'PASS',head:HEAD,base:BASE,findings:[]});
const result={status:0,signal:null};
const pass=()=>validatePersistedCodexPass({
  raw,head:HEAD,base:BASE,result
});
const denied=fn=>assert.throws(fn,/protected_codex_terminal_denied/);

test('real terminal readback shape and status are BOTH mandatory',()=>{
  const p=pass();
  assert.equal(p.verdict,'PASS');
  assert.equal(p.head,HEAD);
  assert.equal(p.base,BASE);
  assert.equal(p.terminalSha256,
    createHash('sha256').update(raw).digest('hex'));
  for(const changed of [
    {status:1,signal:null},{status:0,signal:'SIGTERM'},
    {status:0,signal:null,error:Error('timed out')},
    {status:0,signal:null,outputOverflow:true},
    {status:null,signal:'SIGKILL'}
  ])denied(()=>validatePersistedCodexPass({
    raw,head:HEAD,base:BASE,result:changed
  }));
});
test('CLI exit zero without exact persisted PASS always fails closed',()=>{
  for(const bad of [
    '', 'PASS', 'CLI exit 0; PASS',
    JSON.stringify({verdict:'FAIL',head:HEAD,base:BASE,
      findings:['privilege escalation']}),
    JSON.stringify({verdict:'PASS',head:'d'.repeat(40),
      base:BASE,findings:[]}),
    JSON.stringify({verdict:'PASS',head:HEAD,
      base:'d'.repeat(40),findings:[]}),
    JSON.stringify({verdict:'PASS',head:HEAD,
      base:BASE,findings:['suppressed']}),
    JSON.stringify({verdict:'PASS',head:HEAD,
      base:BASE,findings:[],extra:'yes'}),
    raw.replace('"verdict":"PASS"','"verdict":"FAIL","verdict":"PASS"'),
    '~~~json\n'+raw+'\n~~~',
    raw.slice(0,raw.length-4),
    ' '+raw.slice(0,-1)+' ' + raw.slice(-1)
  ])denied(()=>validatePersistedCodexPass({
    raw:bad,head:HEAD,base:BASE,result
  }));
  denied(()=>validatePersistedCodexPass({
    raw,head:HEAD,base:HEAD,result
  }));
});
test('receipt constructor accepts validated structured result, not arbitrary text',()=>{
  const terminal=pass();
  const claim=makeCodexReceiptClaim({
    terminal,head:HEAD,base:BASE,reviewRunId:RUN,nowMs:NOW
  });
  const data=JSON.parse(claim);
  assert.equal(data.version,1);
  assert.equal(data.prNumber,39);
  assert.equal(data.reviewRunId,RUN);
  assert.equal(data.reviewVerdict,'PASS');
  assert.equal(data.expiresAtMs,NOW+120000);
  for(const changed of [
    {terminal:{verdict:'PASS',head:HEAD,base:BASE}},
    {terminal:{...terminal,verdict:'FAIL'}},
    {terminal:{...terminal,base:'d'.repeat(40)}},
    {reviewRunId:'worker-chosen'},
    {nowMs:0}
  ])denied(()=>makeCodexReceiptClaim({
    terminal,head:HEAD,base:BASE,
    reviewRunId:RUN,nowMs:NOW,...changed
  }));
});
test('synthetic signed claim remains receipt-shaped, not operational proof',()=>{
  const reviewer=generateKeyPairSync('ed25519');
  const approver=generateKeyPairSync('ed25519');
  const json=makeCodexReceiptClaim({
    terminal:pass(),head:HEAD,base:BASE,reviewRunId:RUN,nowMs:NOW
  });
  const signatureBase64=sign(null,Buffer.from(
    INDEPENDENT_REVIEW_DOMAIN+json),reviewer.privateKey).toString('base64');
  const verified=verifyIndependentSignedReview({
    reviewJson:json,signatureBase64,
    pinnedReviewerPublicKeyPem:reviewer.publicKey.export({
      format:'pem',type:'spki'
    }),
    pinnedApprovalPublicKeyPem:approver.publicKey.export({
      format:'pem',type:'spki'
    }),head:HEAD,base:BASE,prNumber:39,nowMs:NOW+1000
  });
  assert.equal(verified.reviewRunId,RUN);
});
test('signer cannot run from checkout or accept Worker-supplied PASS JSON',()=>{
  const path=fileURLToPath(new URL(
    '../scripts/protected-update-codex-receipt.mjs',import.meta.url));
  for(const args of [[],['--pass','--sign']]){
    const r=spawnSync(process.execPath,[path,...args],{
      encoding:'utf8',input:raw,timeout:3000,maxBuffer:4096
    });
    assert.equal(r.status,78);
    assert.equal(r.stdout,'');
    assert.match(r.stderr,/protected_codex_execution_denied_or_unknown/);
  }
});
test('runner and verifier are in exact, uninstalled source-only package',()=>{
  for(const name of [
    'scripts/protected-update-codex-receipt.mjs',
    'src/ops/protected-update-codex-terminal.mjs',
    'src/ops/protected-update-github-evidence.mjs'
  ])assert.ok(PROTECTED_BOOTSTRAP_FILES.includes(name));
});

test('bounded pinned runtime accepts the actually installed CLI and companion sizes',()=>{
  // Recorded read-only root-owned executable metadata, not binary fixture bytes.
  for(const bytes of [72160,77997328,319346888,384*1024*1024])
    assert.equal(supportedProtectedExecutableSize(bytes),true);
  for(const bytes of [0,-1,384*1024*1024+1,Number.MAX_SAFE_INTEGER,
   Infinity,1.5,'319346888'])
    assert.equal(supportedProtectedExecutableSize(bytes),false);
});

test('Codex review input authenticates every immutable pack source, not a hash-only text',()=>{
 const files=PROTECTED_BOOTSTRAP_FILES.map((path,i)=>({
  path,content:'// synthetic source '+i+'\n'
 }));
 const rows=files.map(({path,content})=>({
  path,bytes:Buffer.byteLength(content,'utf8'),
  sha256:createHash('sha256').update(content).digest('hex')
 }));
 const manifestJson=JSON.stringify({version:1,
  repository:'al-hub/mcp-dev-hub',head:HEAD,installAuthorized:false,
  requiredIndependentIssuers:['independent-codex','protected-approval'],
  files:rows});
 const digest=createHash('sha256').update(manifestJson).digest('hex');
 const raw=makePinnedCodexReviewInput({manifestJson,files});
 const input=validatePinnedCodexSourceReviewInput({
  raw,head:HEAD,packDigest:digest});
 assert.equal(input.fileCount,PROTECTED_BOOTSTRAP_FILES.length);
 assert.equal(input.sha256,createHash('sha256').update(raw).digest('hex'));
 assert.ok(input.readable.includes('// synthetic source 0'));
 for(const wrong of [
  {raw:JSON.stringify({...JSON.parse(raw),
    files:files.slice(0,-1)})},
  {raw:JSON.stringify({...JSON.parse(raw),
    files:[...files.slice(0,-1),
      {...files.at(-1),content:'// changed'}]})},
  {head:BASE},{packDigest:'f'.repeat(64)}
 ])denied(()=>validatePinnedCodexSourceReviewInput({
  raw,head:HEAD,packDigest:digest,...wrong
 }));
});
test('v2 receipt binds immutable pack, complete input and terminal hashes',()=>{
 const k=generateKeyPairSync('ed25519');
 const approver=generateKeyPairSync('ed25519');
 const packDigest='d'.repeat(64),reviewInputSha256='e'.repeat(64);
 const claim=makeCodexReceiptClaim({
  terminal:pass(),head:HEAD,base:BASE,reviewRunId:RUN,nowMs:NOW,
  packDigest,reviewInputSha256
 });
 assert.equal(JSON.parse(claim).version,2);
 const signatureBase64=sign(null,Buffer.from(
  INDEPENDENT_REVIEW_DOMAIN_V2+claim),k.privateKey).toString('base64');
 const a={reviewJson:claim,signatureBase64,
  pinnedReviewerPublicKeyPem:k.publicKey.export({type:'spki',format:'pem'}),
  pinnedApprovalPublicKeyPem:approver.publicKey.export({type:'spki',format:'pem'}),
  head:HEAD,base:BASE,prNumber:39,nowMs:NOW+1,
  requiredPackDigest:packDigest};
 assert.equal(verifyIndependentSignedReview(a).reviewRunId,RUN);
 assert.throws(()=>verifyIndependentSignedReview({
  ...a,requiredPackDigest:'f'.repeat(64)
 }));
 assert.throws(()=>verifyIndependentSignedReview({
  ...a,signatureBase64:sign(null,Buffer.from(
   INDEPENDENT_REVIEW_DOMAIN+claim),k.privateKey).toString('base64')
 }));
 const legacy=makeCodexReceiptClaim({terminal:pass(),head:HEAD,base:BASE,
  reviewRunId:RUN,nowMs:NOW});
 assert.throws(()=>verifyIndependentSignedReview({
  ...a,reviewJson:legacy,
  signatureBase64:sign(null,Buffer.from(
   INDEPENDENT_REVIEW_DOMAIN+legacy),k.privateKey).toString('base64')
 }));
});

test('fixed signer validates complete source against root-pinned manifest before Codex signs v2',()=>{
 const body=readFileSync(new URL(
  '../scripts/protected-update-codex-receipt.mjs',import.meta.url),'utf8');
 const i=body.indexOf('validatePinnedCodexSourceReviewInput({');
 const dispatched=body.indexOf('writeOnce(PRIVATE+',i);
 const final=body.indexOf('runRealCodex(packet,checked.readable)',dispatched);
 assert.ok(i>0&&dispatched>i&&final>dispatched);
 assert.ok(body.includes('max:2*1024*1024'));
 assert.ok(body.includes('INDEPENDENT_REVIEW_DOMAIN_V2+reviewJson'));
 assert.ok(body.includes('packDigest:packet.packDigest'));
});
