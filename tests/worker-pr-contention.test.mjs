import test from 'node:test';
import assert from 'node:assert/strict';
import {DatabaseSync} from 'node:sqlite';
import {mkdtempSync,rmSync} from 'node:fs';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {trackPr,recordPrGate,prNextAction} from '../src/jobs/pr-automation.mjs';
import {openDb,enqueuePrReviewIfReady} from '../scripts/worker.mjs';

const shaA='a'.repeat(40),shaB='b'.repeat(40),prKey='al-hub/mcp-dev-hub#17';
test('race: two pollers cannot enqueue duplicate AI review of same SHA',async()=>{
 const dir=mkdtempSync(join(tmpdir(),'mcp-race-'));
 const keys=['MCP_DEV_HUB_STATE_DIR','MCP_DEV_HUB_APPROVED_SCOPE','MCP_DEV_HUB_WORKTREE_ROOT','MCP_DEV_HUB_WORKTREE_REPO','MCP_DEV_HUB_AUTOMATION_PR_KEY'];
 const saved=Object.fromEntries(keys.map(k=>[k,process.env[k]]));
 Object.assign(process.env,{MCP_DEV_HUB_STATE_DIR:dir,MCP_DEV_HUB_APPROVED_SCOPE:'demo:local:test',
 MCP_DEV_HUB_WORKTREE_ROOT:dir,MCP_DEV_HUB_WORKTREE_REPO:dir,MCP_DEV_HUB_AUTOMATION_PR_KEY:prKey});
 try{
  const a=openDb(),b=openDb();
  trackPr(a,{prKey,headSha:shaA});
  const result={gate:'independent_review',state:'blocked',headSha:shaA};
  const attempts=await Promise.allSettled([Promise.resolve().then(()=>enqueuePrReviewIfReady(a,result)),Promise.resolve().then(()=>enqueuePrReviewIfReady(b,result))]);
  assert.equal(attempts.filter(x=>x.status==='fulfilled'&&x.value===true).length,1);
  assert.equal(a.prepare("SELECT COUNT(*) AS n FROM jobs WHERE kind='review-opencode'").get().n,1);
  assert.equal(b.prepare('SELECT COUNT(*) AS n FROM review_attempts').get().n,1);
  a.close();b.close();
 }finally{
  for(const [k,v] of Object.entries(saved)){if(v===undefined)delete process.env[k];else process.env[k]=v;}
  rmSync(dir,{recursive:true,force:true});
 }
});
test('race: SHA transition invalidates prior CI and independent review evidence',()=>{
 const db=new DatabaseSync(':memory:');
 trackPr(db,{prKey,headSha:shaA});
 recordPrGate(db,{prKey,headSha:shaA,gate:'ci',verdict:'passed',evidenceId:'ci-a'});
 recordPrGate(db,{prKey,headSha:shaA,gate:'independent_review',verdict:'passed',evidenceId:'approval-a'});
 trackPr(db,{prKey,headSha:shaB});
 assert.equal(prNextAction(db,{prKey,observedSha:shaA}).action,'reconcile');
 assert.equal(prNextAction(db,{prKey,observedSha:shaB}).gate,'ci');
 assert.equal(db.prepare('SELECT COUNT(*) AS n FROM pr_gate_evidence').get().n,0);
 assert.throws(()=>recordPrGate(db,{prKey,headSha:shaA,gate:'security',verdict:'passed',evidenceId:'old'}),/stale/);
 db.close();
});
test('race: blocked independent review must never become merge eligible from CI success alone',()=>{
 const db=new DatabaseSync(':memory:');
 trackPr(db,{prKey,headSha:shaA});
 recordPrGate(db,{prKey,headSha:shaA,gate:'ci',verdict:'passed',evidenceId:'ci-a'});
 recordPrGate(db,{prKey,headSha:shaA,gate:'independent_review',verdict:'blocked',evidenceId:'none'});
 assert.equal(prNextAction(db,{prKey,observedSha:shaA}).action,'remediate_or_block');
 db.close();
});

test('race: stale SHA cannot mutate the new HEAD gate after turnover',()=>{
 const db=new DatabaseSync(':memory:');
 trackPr(db,{prKey,headSha:shaA});
 trackPr(db,{prKey,headSha:shaB});
 recordPrGate(db,{prKey,headSha:shaB,gate:'ci',verdict:'passed',evidenceId:'fresh-ci'});
 assert.throws(()=>recordPrGate(db,{prKey,headSha:shaA,gate:'ci',verdict:'passed',evidenceId:'stale-ci'}),/stale/);
 const fresh=db.prepare('SELECT head_sha,evidence_id FROM pr_gate_evidence WHERE gate=?').get('ci');
 assert.equal(fresh.head_sha,shaB);
 assert.equal(fresh.evidence_id,'fresh-ci');
 db.close();
});
