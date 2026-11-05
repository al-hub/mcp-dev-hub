import test from 'node:test';
import assert from 'node:assert/strict';
import {DatabaseSync} from 'node:sqlite';
import {
 CANARY_JOB_ID,CANARY_REPO,CANARY_PATH,CANARY_BRANCH,
 canaryAuthorized,validateCandidate,ensureCanaryTable,
 startCanary,advanceCanary,blockCanary
} from '../src/jobs/ai-github-canary-policy.mjs';

const sha='a'.repeat(40);
const sample=[
 "import test from 'node:test';",
 "import assert from 'node:assert/strict';",
 "import {safeBearer} from '../src/dashboard/read-only-server.mjs';",
 "test('valid 24 and invalid 23',()=>{",
 " const valid='x'.repeat(24),short='y'.repeat(23);",
 " assert.equal(safeBearer('Bearer '+valid,valid),true);",
 " assert.equal(safeBearer('Bearer '+short,short),false);",
 "});"
].join('\n');
const job={id:CANARY_JOB_ID,kind:'ai-github-canary',project:'demo',target:'local',workspace:'stage',state:'queued'};
test('job scope and all distinct grants are mandatory, with no generic authority',()=>{
 const args={job,scope:'demo:local:stage',write:'1',push:'1',enabled:'1'};
 assert.equal(canaryAuthorized(args),true);
 for(const key of ['write','push','enabled'])assert.equal(canaryAuthorized({...args,[key]:'0'}),false);
 assert.equal(canaryAuthorized({...args,scope:'other:local:stage'}),false);
 assert.equal(canaryAuthorized({...args,job:{...job,id:'other-job'}}),false);
 assert.equal(canaryAuthorized({...args,job:{...job,state:'succeeded'}}),false);
 assert.equal(canaryAuthorized({...args,job:{...job,target:'remote'}}),false);
 assert.equal(CANARY_REPO,'al-hub/mcp-dev-hub');
 assert.ok(CANARY_BRANCH.startsWith('test/23-'));
 assert.ok(CANARY_PATH.startsWith('tests/'));
});
test('candidate code accepts only a bounded public test with exact imports',()=>{
 assert.equal(validateCandidate(sample),true);
 assert.equal(validateCandidate(''),false);
 assert.equal(validateCandidate(sample.replace("node:test","node:fs")),false);
 assert.equal(validateCandidate(sample+' \nrequire("fs")'),false);
 assert.equal(validateCandidate(sample+' \nprocess.env.HOME'),false);
 assert.equal(validateCandidate(sample+' \nfetch("https://invalid.example")'),false);
 assert.equal(validateCandidate(sample+' \n'+('x'.repeat(8000))),false);
 assert.equal(validateCandidate(sample.replace("safeBearer","otherThing")),false);
 assert.equal(validateCandidate(sample+' \nimport("node:os")'),false);
});
test('single-use durable canary cannot replay or leap over a gate',()=>{
 const db=new DatabaseSync(':memory:');
 try{
  ensureCanaryTable(db);
  assert.throws(()=>startCanary(db,{jobId:'another',baseSha:sha}),/unauthorized/);
  assert.equal(startCanary(db,{jobId:CANARY_JOB_ID,baseSha:sha}),true);
  assert.throws(()=>startCanary(db,{jobId:CANARY_JOB_ID,baseSha:sha}),/replay/);
  assert.throws(()=>advanceCanary(db,{from:'started',to:'content_uploaded'}),/unauthorized/);
  advanceCanary(db,{from:'started',to:'branch_dispatching'});
  advanceCanary(db,{from:'branch_dispatching',to:'branch_created'});
  assert.throws(()=>advanceCanary(db,{from:'branch_dispatching',to:'branch_created'}),/stale/);
  advanceCanary(db,{from:'branch_created',to:'source_generated'});
  advanceCanary(db,{from:'source_generated',to:'content_dispatching'});
  advanceCanary(db,{from:'content_dispatching',to:'content_uploaded',headSha:sha});
  advanceCanary(db,{from:'content_uploaded',to:'pr_dispatching'});
  advanceCanary(db,{from:'pr_dispatching',to:'pr_created',prNumber:123});
  assert.throws(()=>advanceCanary(db,{from:'pr_created',to:'ci_passed',headSha:'bad'}),/invalid HEAD/);
  advanceCanary(db,{from:'pr_created',to:'ci_passed'});
  advanceCanary(db,{from:'ci_passed',to:'review_dispatching'});
  advanceCanary(db,{from:'review_dispatching',to:'review_passed'});
  advanceCanary(db,{from:'review_passed',to:'merge_dispatching'});
  advanceCanary(db,{from:'merge_dispatching',to:'merged',mergeSha:'b'.repeat(40)});
  advanceCanary(db,{from:'merged',to:'succeeded',evidence:'github:ci:999'});
  const final=db.prepare('SELECT phase,head_sha,pr_number,merge_sha,evidence FROM ai_github_canary').get();
  assert.equal(final.phase,'succeeded');
  assert.equal(final.pr_number,123);
  assert.equal(final.head_sha,sha);
  assert.equal(final.merge_sha,'b'.repeat(40));
  assert.equal(blockCanary(db,{phase:'succeeded',reason:'unexpected_change'}),true);
  assert.equal(blockCanary(db,{phase:'succeeded',reason:'duplicate'}),false);
 }finally{db.close()}
});
test('uncertain remote-effect state is terminal and prevents a second dispatch',()=>{
 const db=new DatabaseSync(':memory:');
 try{
  startCanary(db,{jobId:CANARY_JOB_ID,baseSha:sha});
  advanceCanary(db,{from:'started',to:'branch_dispatching'});
  assert.equal(blockCanary(db,{phase:'branch_dispatching',reason:'remote_effect_unknown',uncertain:true}),true);
  assert.equal(db.prepare('SELECT phase,last_reason FROM ai_github_canary').get().phase,'unknown');
  assert.throws(()=>advanceCanary(db,{from:'branch_dispatching',to:'branch_created'}),/stale/);
  assert.throws(()=>startCanary(db,{jobId:CANARY_JOB_ID,baseSha:sha}),/replay/);
 }finally{db.close()}
});
