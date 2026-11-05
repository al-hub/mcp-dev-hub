import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {verifiedStrictGitHubProtection} from '../src/jobs/ai-github-canary-policy.mjs';

const fixture=()=>({
 required_status_checks:{
  strict:true,contexts:['bootstrap'],checks:[{context:'bootstrap',app_id:15368}]
 },
 enforce_admins:{enabled:true},
 allow_force_pushes:{enabled:false}
});
test('Server-side strict main protection is required without admin bypass',()=>{
 assert.equal(verifiedStrictGitHubProtection(fixture()),true);
 const p=fixture();p.required_status_checks.strict=false;
 assert.equal(verifiedStrictGitHubProtection(p),false);
 const wrong=fixture();wrong.required_status_checks.checks[0].app_id=1;
 assert.equal(verifiedStrictGitHubProtection(wrong),false);
 const noCtx=fixture();noCtx.required_status_checks.contexts=[];
 assert.equal(verifiedStrictGitHubProtection(noCtx),false);
 const noAdmins=fixture();noAdmins.enforce_admins.enabled=false;
 assert.equal(verifiedStrictGitHubProtection(noAdmins),false);
 const force=fixture();force.allow_force_pushes.enabled=true;
 assert.equal(verifiedStrictGitHubProtection(force),false);
 assert.equal(verifiedStrictGitHubProtection(null),false);
});
test('Verified strict base and exact HEAD are checked before protected merge',()=>{
 const s=readFileSync(new URL('../scripts/ai-github-canary.mjs',import.meta.url),'utf8');
 const begin=s.indexOf("  if(mainSha()!==base)throw Error('main_changed_before_merge');");
 const checked=s.indexOf("  verifyPr(prNumber,head,base);",begin);
 const strict=s.indexOf("  requireProtection();",checked);
 const dispatch=s.indexOf("  advance('merge_dispatching');",strict);
 const merge=s.indexOf("  const merged=gh(BASE+'/pulls/'+prNumber+'/merge'",dispatch);
 assert.ok(begin>0 && checked>begin && strict>checked && dispatch>strict && merge>dispatch);
 assert.match(s,/sha:head,merge_method:'merge'/);
 assert.match(s,/merged\.merged!==true/);
});
test('GitHub mutation scope remains bound to this PR, never raw ref update to main',()=>{
 const s=readFileSync(new URL('../scripts/ai-github-canary.mjs',import.meta.url),'utf8');
 const a=s.indexOf('const approved=['),b=s.indexOf('];',a);
 assert.ok(a>0 && b>a);
 const allowlist=s.slice(a,b);
 assert.match(allowlist,/\/merge/);
 assert.doesNotMatch(allowlist,/git\/refs\/heads\/main/);
 assert.doesNotMatch(allowlist,/\/branches\/main\/protection\$/m);
 assert.doesNotMatch(s,/force:true/);
});
