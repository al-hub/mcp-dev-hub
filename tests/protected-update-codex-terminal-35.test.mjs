import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {
  validatePersistedCodexPass,makeCodexReceiptClaim
} from '../src/ops/protected-update-codex-terminal.mjs';
import {INDEPENDENT_REVIEW_DOMAIN,verifyIndependentSignedReview}
  from '../src/ops/protected-update-github-evidence.mjs';
import {PROTECTED_BOOTSTRAP_FILES}
  from '../scripts/protected-update-bootstrap-pack.mjs';

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
