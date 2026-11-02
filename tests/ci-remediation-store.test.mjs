import test from 'node:test';
import assert from 'node:assert/strict';
import {DatabaseSync} from 'node:sqlite';
import {claimCiRemediation,acknowledgeCiFix} from '../src/jobs/ci-remediation-store.mjs';
test('atomic fix claim prevents duplicate and requires new SHA',()=>{
 const db=new DatabaseSync(':memory:');const prKey='al-hub/mcp-dev-hub#17',sha='a'.repeat(40);
 const args={prKey,headSha:sha,observedSha:sha,reason:'test_failure',reviewerIndependent:true};
 assert.equal(claimCiRemediation(db,args).state,'dispatching');
 assert.equal(claimCiRemediation(db,args).allowed,false);
 assert.equal(acknowledgeCiFix(db,{prKey,newSha:sha,dispatched:true}),false);
 assert.equal(db.prepare('SELECT state,attempts FROM ci_remediations').get().state,'awaiting_new_sha');
 assert.equal(db.prepare('SELECT attempts FROM ci_remediations').get().attempts,1);
 db.close();
});
test('unknown dispatch is never automatically replayed',()=>{
 const db=new DatabaseSync(':memory:');const prKey='al-hub/mcp-dev-hub#17',sha='a'.repeat(40);
 claimCiRemediation(db,{prKey,headSha:sha,observedSha:sha,reason:'compile_failure',reviewerIndependent:true});
 assert.equal(acknowledgeCiFix(db,{prKey,newSha:'b'.repeat(40),dispatched:false}),false);
 assert.equal(claimCiRemediation(db,{prKey,headSha:sha,observedSha:sha,reason:'compile_failure',reviewerIndependent:true}).state,'unknown');
 db.close();
});
