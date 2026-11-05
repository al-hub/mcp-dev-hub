import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';

test('Worker canary may not invoke GitHub head-only direct merge without atomic reviewed-base gate',()=>{
 const source=readFileSync(new URL('../scripts/ai-github-canary.mjs',import.meta.url),'utf8');
 // Regression guard: the PR Head-only REST merge API is not the server-side
 // approval of the independently reviewed HEAD + BASE pair.
 assert.doesNotMatch(source,/pulls\/['"+]?\+prNumber\+['"]?\/merge/);
 assert.doesNotMatch(source,/gh\(BASE\+['"]\/pulls\/['"]\+prNumber\+['"]\/merge['"]/);
 assert.match(source,/const reason='atomic_base_merge_unavailable'/);
 assert.match(source,/blockCanary\(db,\{phase,reason,uncertain:false\}\)/);
 assert.match(source,/return \{state:'blocked',reason,phase,jobId,prNumber,head,base/);
});

test('cannot accidentally whitelist a HEAD-only GitHub merge mutation',()=>{
 const source=readFileSync(new URL('../scripts/ai-github-canary.mjs',import.meta.url),'utf8');
 const start=source.indexOf('const approved=['),end=source.indexOf('];',start);
 assert.ok(start>=0 && end>start);
 const allowList=source.slice(start,end);
 assert.doesNotMatch(allowList,/\/merge/);
 assert.doesNotMatch(source,/merge_method:'merge'/);
});
