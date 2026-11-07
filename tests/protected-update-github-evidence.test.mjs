import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {
  INDEPENDENT_REVIEW_DOMAIN,verifyIndependentSignedReview,
  validateGitHubEvidenceShape,fetchAndVerifyGitHubUpdateEvidence,
  validateGitHubControllerSource,fetchAndVerifyGitHubControllerPair
} from '../src/ops/protected-update-github-evidence.mjs';

const head='a'.repeat(40),base='b'.repeat(40);
const prNumber=39,ciRunId=42205306154,now=1793950000000;
const independent=generateKeyPairSync('ed25519');
const approval=generateKeyPairSync('ed25519');
const other=generateKeyPairSync('ed25519');
const pem=kp=>kp.publicKey.export({type:'spki',format:'pem'});
const review=()=>({
  version:1,repository:'al-hub/mcp-dev-hub',prNumber,head,base,
  reviewer:'independent-codex',reviewRunId:'1'.repeat(32),
  reviewVerdict:'PASS',findings:[],
  issuedAtMs:now-1000,expiresAtMs:now+30000
});
function signed(value=review(),key=independent){
  const json=typeof value==='string'?value:JSON.stringify(value);
  const signatureBase64=sign(null,
    Buffer.from(INDEPENDENT_REVIEW_DOMAIN+json),key.privateKey)
    .toString('base64');
  return {
    reviewJson:json,signatureBase64,
    pinnedReviewerPublicKeyPem:pem(independent),
    pinnedApprovalPublicKeyPem:pem(approval),
    head,base,prNumber,nowMs:now
  };
}
const expectedDigest=raw=>createHash('sha256').update(raw).digest('hex');
function githubFixture(){
  return {
    prNumber,head,base,ciRunId,
    pr:{
      number:prNumber,state:'open',draft:false,
      head:{sha:head,repo:{full_name:'al-hub/mcp-dev-hub'}},
      base:{sha:base,ref:'main',repo:{full_name:'al-hub/mcp-dev-hub'}}
    },
    run:{
      id:ciRunId,name:'CI',event:'pull_request',
      path:'.github/workflows/ci.yml',workflow_id:402358309,
      status:'completed',conclusion:'success',head_sha:head,
      repository:{full_name:'al-hub/mcp-dev-hub'},
      pull_requests:[{number:prNumber,head:{sha:head},base:{sha:base}}]
    },
    jobs:{
      total_count:1,
      jobs:[{
        name:'bootstrap',status:'completed',conclusion:'success',
        steps:[{name:'Run npm run check',conclusion:'success'}]
      }]
    },
    protection:{
      required_pull_request_reviews:null,
      required_status_checks:{
        strict:true,contexts:['bootstrap'],
        checks:[{context:'bootstrap',app_id:15368}]
      },
      enforce_admins:{enabled:true},
      allow_force_pushes:{enabled:false},
      allow_deletions:{enabled:false},
      required_conversation_resolution:{enabled:true}
    }
  };
}
test('signed independent review binds exact SHA/base and distinct trust keys',()=>{
  const args=signed();
  const r=verifyIndependentSignedReview(args);
  assert.deepEqual(r,{
    head,base,prNumber,reviewRunId:'1'.repeat(32),
    reviewDigest:expectedDigest(args.reviewJson)
  });
  assert.equal(Object.isFrozen(r),true);
});
test('signature, self-signing, wrong signer, subject and timestamps denied',()=>{
  const good=signed();
  const tamperedSignature=Buffer.from(good.signatureBase64,'base64');
  tamperedSignature[0]^=1;
  for(const patch of [
    {signatureBase64:tamperedSignature.toString('base64')},
    {pinnedReviewerPublicKeyPem:pem(other)},
    {pinnedApprovalPublicKeyPem:pem(independent)},
    {head:base},{base:head},{prNumber:40},
    {nowMs:now+30001},{nowMs:now-1001},
    {signatureBase64:'AA=='}
  ])assert.throws(()=>verifyIndependentSignedReview({...good,...patch}),
    /protected_evidence_denied/);
});
test('review inputs are canonical, bounded and cannot claim conditional pass',()=>{
  const bad=[
    {...review(),reviewVerdict:'CONDITIONAL'},
    {...review(),findings:['warning']},
    {...review(),head:[head]},
    {...review(),reviewRunId:['1'.repeat(32)]},
    {...review(),reviewer:'worker'},
    {...review(),repository:'other/owner'},
    {...review(),expiresAtMs:now+600001},
    {...review(),extra:true}
  ];
  for(const item of bad)
    assert.throws(()=>verifyIndependentSignedReview(signed(item)),
      /protected_evidence_denied/);
  const raw=JSON.stringify(review());
  for(const malformed of [
    raw.replace('"version":1','"version":1,"version":1'),
    ' '+raw,raw.replace('"findings":','"findings": ')
  ])assert.throws(()=>verifyIndependentSignedReview(signed(malformed)),
    /protected_evidence_denied/);
});
test('authenticated GitHub payload shape requires exact PR, CI job and protection',()=>{
  const f=githubFixture();
  const result=validateGitHubEvidenceShape(f);
  assert.equal(Object.isFrozen(result),true);
  assert.deepEqual(result,{
    head,base,ciRunId,ciHead:head,ciPassed:true,strictProtection:true
  });
  const failures=[
    {...f,pr:{...f.pr,draft:true}},
    {...f,pr:{...f.pr,head:{...f.pr.head,sha:base}}},
    {...f,pr:{...f.pr,base:{...f.pr.base,sha:head}}},
    {...f,run:{...f.run,head_sha:base}},
    {...f,run:{...f.run,event:'workflow_dispatch'}},
    {...f,run:{...f.run,path:'.github/workflows/unrelated.yml'}},
    {...f,run:{...f.run,workflow_id:99999999}},
    {...f,run:{...f.run,conclusion:'failure'}},
    {...f,run:{...f.run,pull_requests:[]}},
    {...f,run:{...f.run,pull_requests:[{
      number:prNumber,head:{sha:head},base:{sha:'0'.repeat(40)}
    }]}},
    {...f,run:{...f.run,pull_requests:[{
      number:prNumber,head:{sha:'0'.repeat(40)},base:{sha:base}
    }]}},
    {...f,jobs:{...f.jobs,total_count:101}},
    {...f,jobs:{total_count:1,jobs:[
      {name:'bootstrap',status:'completed',conclusion:'success',steps:[]}
    ]}},
    {...f,protection:{...f.protection,
      required_status_checks:{...f.protection.required_status_checks,
        strict:false}}},
    {...f,protection:{...f.protection,
      required_pull_request_reviews:undefined}},
    {...f,protection:{...f.protection,
      required_pull_request_reviews:{
        required_approving_review_count:0
      }}},
    {...f,protection:{...f.protection,
      required_pull_request_reviews:{
        required_approving_review_count:1,
        dismiss_stale_reviews:true,require_last_push_approval:true
      }}},
    {...f,protection:{...f.protection,allow_force_pushes:{enabled:true}}},
    {...f,protection:{...f.protection,
      required_conversation_resolution:{enabled:false}}}
  ];
  for(const item of failures)
    assert.throws(()=>validateGitHubEvidenceShape(item),
      /protected_evidence_denied/);
});
test('live GitHub fetch fails before network for unsigned or invalid evidence',async()=>{
  const good=signed();
  await assert.rejects(fetchAndVerifyGitHubUpdateEvidence({
    ...good,reviewSignatureBase64:'AA==',githubToken:'not-a-real-token',
    ciRunId
  }),/protected_evidence_denied/);
  await assert.rejects(fetchAndVerifyGitHubUpdateEvidence({
    ...good,reviewSignatureBase64:good.signatureBase64,
    githubToken:'not-a-real-token',ciRunId,prNumber:0
  }),/protected_evidence_denied/);
});

test('fixed GitHub controller bytes are bound to signed file hash and path',()=>{
  const data=Buffer.from('synthetic-fixed-controller\n');
  const file='ai-github-canary.mjs';
  const args={
    name:file,head,bytes:data.length,sha256:createHash('sha256')
      .update(data).digest('hex')
  };
  const blob={
    type:'file',path:'scripts/ai-github-canary.mjs',
    name:file,encoding:'base64',size:data.length,
    sha:'f'.repeat(40),content:data.toString('base64')+'\n'
  };
  assert.deepEqual(validateGitHubControllerSource(blob,args),data);
  for(const mutation of [
    {path:'../private-file'},
    {type:'symlink'},
    {name:'bad.mjs'},
    {encoding:'utf-8'},
    {size:data.length+1},
    {sha:'invalid'},
    {content:Buffer.from('changed').toString('base64')}
  ])assert.throws(()=>validateGitHubControllerSource({
    ...blob,...mutation
  },args),/protected_evidence_denied/);
  assert.throws(()=>validateGitHubControllerSource(blob,{
    ...args,sha256:'0'.repeat(64)
  }),/protected_evidence_denied/);
});
test('untrusted manifest allowlist and hashes are denied before GitHub fetch',async()=>{
  const good=[
    {name:'ai-github-canary.mjs',bytes:20,sha256:'a'.repeat(64)},
    {name:'ai-github-canary-policy.mjs',bytes:20,sha256:'b'.repeat(64)}
  ];
  for(const list of [
    [good[0]],
    [good[0],{...good[0]}],
    [{...good[0],name:'../../../etc/passwd'},good[1]],
    [good[0],{...good[1],sha256:'invalid'}]
  ])await assert.rejects(fetchAndVerifyGitHubControllerPair({
    head,manifestFiles:list,githubToken:'not-a-real-token'
  }),/protected_evidence_denied/);
});

test('unrelated PR policy still requires mandatory independent reviews',()=>{
  const f=githubFixture();
  const pr17={...f,prNumber:17,
    pr:{...f.pr,number:17},
    run:{...f.run,pull_requests:[{number:17,head:{sha:head},base:{sha:base}}]}};
  assert.throws(()=>validateGitHubEvidenceShape(pr17),/protected_evidence_denied/);
  const secured={...pr17,protection:{...f.protection,
    required_pull_request_reviews:{
      required_approving_review_count:1,
      dismiss_stale_reviews:true,require_last_push_approval:true
    }}};
  assert.equal(validateGitHubEvidenceShape(secured).strictProtection,true);
});
