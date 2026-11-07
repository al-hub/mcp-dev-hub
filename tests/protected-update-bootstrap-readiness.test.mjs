import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {
  matchProtectedBaselinePair,inspectExistingProtectedBootstrapBaseline
} from '../scripts/protected-update-bootstrap-readiness.mjs';

const DENIED=/protected_bootstrap_readiness_denied/;
const bytes=(word)=>Buffer.from('synthetic original '+word);
test('exact independently captured original pair binds identical bytes',()=>{
  const a=bytes('policy'),b=bytes('controller');
  const proof=matchProtectedBaselinePair({
    actualPolicy:a,expectedPolicy:Buffer.from(a),
    actualController:b,expectedController:Buffer.from(b)
  });
  assert.deepEqual(proof.map(x=>x.name),[
    'ai-github-canary-policy.mjs','ai-github-canary.mjs'
  ]);
  assert.equal(proof.length,2);
  assert.equal(proof[0].bytes,a.length);
});
test('different installed policy/controller bytes fail closed',()=>{
  const a=bytes('policy'),b=bytes('controller');
  for(const field of ['expectedPolicy','expectedController']){
    const args={
      actualPolicy:a,expectedPolicy:Buffer.from(a),
      actualController:b,expectedController:Buffer.from(b)
    };
    args[field]=bytes('tampered');
    assert.throws(()=>matchProtectedBaselinePair(args),DENIED);
  }
});
test('special/missing/empty/oversized fixture inputs fail',()=>{
  const a=bytes('policy'),b=bytes('controller');
  for(const bad of [null,'text',Buffer.alloc(0),
    Buffer.alloc(256*1024+1)]){
    assert.throws(()=>matchProtectedBaselinePair({
      actualPolicy:a,expectedPolicy:bad,
      actualController:b,expectedController:b
    }),DENIED);
  }
});
test('no caller can make this informational check install anything',()=>{
  assert.throws(()=>inspectExistingProtectedBootstrapBaseline({
    repositoryPath:'relative',baselineCommit:'a'.repeat(40)
  }),DENIED);
});
test('CLI rejects unknown args before touching real OS',()=>{
  const source=fileURLToPath(new URL(
    '../scripts/protected-update-bootstrap-readiness.mjs',import.meta.url));
  const result=spawnSync(process.execPath,[source,'--root','/tmp'],{
    encoding:'utf8',timeout:5000,maxBuffer:4096
  });
  assert.equal(result.status,1);
  assert.match(result.stderr,DENIED);
  assert.equal(result.stdout,'');
});
