import test from 'node:test';
import assert from 'node:assert/strict';
import {validateCurrentRequiredGitHubCheck}
  from '../src/ops/protected-update-github-evidence.mjs';

const HEAD='a'.repeat(40),RUN=42715849215,APP=15368;
const JOB=2001,CHECK=2001;
const url=id=>'https://api.github.com/repos/al-hub/mcp-dev-hub/check-runs/'+id;
function fixture(){
 return {
  head:HEAD,ciRunId:RUN,
  jobs:{total_count:1,jobs:[{id:JOB,run_id:RUN,head_sha:HEAD,
   name:'bootstrap',status:'completed',conclusion:'success',
   check_run_url:url(JOB),
   steps:[{name:'Run npm run check',conclusion:'success'}]}]},
  checkRuns:{total_count:1,check_runs:[{
   id:CHECK,name:'bootstrap',head_sha:HEAD,
   status:'completed',conclusion:'success',app:{id:APP}
  }]},
  commitStatuses:[]
 };
}
const fail=args=>assert.throws(
 ()=>validateCurrentRequiredGitHubCheck(args),/protected_evidence_denied/);
test('only latest exact-head trusted-app required check matches selected successful CI job',()=>{
 const f=fixture();
 assert.equal(validateCurrentRequiredGitHubCheck(f).requiredCheckCurrent,true);
 fail({...f,head:'b'.repeat(40)});
 fail({...f,ciRunId:RUN+1});
 fail({...f,checkRuns:{total_count:0,check_runs:[]}});
 fail({...f,checkRuns:{total_count:101,check_runs:f.checkRuns.check_runs}});
 fail({...f,checkRuns:{total_count:2,check_runs:f.checkRuns.check_runs}});
 fail({...f,checkRuns:{total_count:1,check_runs:[{
  ...f.checkRuns.check_runs[0],app:{id:999}}]}});
 fail({...f,checkRuns:{total_count:1,check_runs:[{
  ...f.checkRuns.check_runs[0],head_sha:'f'.repeat(40)}]}});
 fail({...f,jobs:{...f.jobs,jobs:[{
  ...f.jobs.jobs[0],check_run_url:url(999)}]}});
});
test('superseded success never authorizes when newer check is queued or failed',()=>{
 const f=fixture();
 const past=f.checkRuns.check_runs[0];
 for(const newest of [
  {...past,id:CHECK+1,status:'queued',conclusion:null},
  {...past,id:CHECK+1,status:'completed',conclusion:'failure'},
  {...past,id:CHECK+1,status:'completed',conclusion:'cancelled'},
  {...past,id:CHECK+1,status:'completed',conclusion:'skipped'}
 ]){
  fail({...f,checkRuns:{total_count:2,check_runs:[past,newest]}});
 }
});
test('ambiguous commit statuses cannot silently replace trusted current check',()=>{
 const f=fixture();
 for(const state of ['success','pending','failure','error']){
  fail({...f,commitStatuses:[{
   context:'bootstrap',state,sha:HEAD
  }]});
 }
 fail({...f,commitStatuses:null});
 fail({...f,checkRuns:{total_count:1,check_runs:[{
  ...f.checkRuns.check_runs[0],id:CHECK+5}]}});
});
