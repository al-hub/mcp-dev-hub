import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {
  PINNED_CI_SOURCES,validatePinnedCiSources,
  validateGitHubReviewThreads,validateGitHubRulesets,
  validateNoNpmConfigGitTree
} from '../src/ops/protected-update-github-evidence.mjs';
import {PROTECTED_BOOTSTRAP_FILES} from '../scripts/protected-update-bootstrap-pack.mjs';

const prNumber=39;
const blob=(path)=>{const bytes=readFileSync(new URL('../'+path,import.meta.url));
  return {type:'file',path,encoding:'base64',size:bytes.length,
    content:bytes.toString('base64')+'\n'};};
const threads=(nodes,extra={})=>({data:{repository:{pullRequest:{
  number:prNumber,reviewThreads:{nodes,pageInfo:{
    hasNextPage:false,hasPreviousPage:false,...extra}}}}}});
const denied=fn=>assert.throws(fn,/protected_evidence_denied/);

test('P2 CI workflow/package/privacy executables are pinned and in Codex packet',()=>{
 const files=PINNED_CI_SOURCES.map(({path})=>blob(path));
 assert.equal(files.length,4);
 assert.equal(validatePinnedCiSources(files).ciImplementationPinned,true);
 for(const {path} of PINNED_CI_SOURCES)
   assert.ok(PROTECTED_BOOTSTRAP_FILES.includes(path),'review packet omits '+path);
 const changed=files.map(v=>v.path==='package.json'
  ? {...v,content:Buffer.from('{"scripts":{"check":"true"}}').toString('base64'),size:28}:v);
 denied(()=>validatePinnedCiSources(changed));
 denied(()=>validatePinnedCiSources(files.slice(1)));
 denied(()=>validatePinnedCiSources([...files,files[0]]));
 denied(()=>validatePinnedCiSources(files.map(v=>v.path==='.github/workflows/ci.yml'
  ? {...v,content:Buffer.from('name: CI\non: [push]\njobs: {}\n').toString('base64'),size:29}:v)));
});

test('P2 current PR review conversations must be fully resolved',()=>{
 assert.equal(validateGitHubReviewThreads(threads([]),prNumber).conversationResolved,true);
 assert.equal(validateGitHubReviewThreads(threads([{id:'PRRT_123',isResolved:true}]),prNumber).conversationResolved,true);
 for(const data of [
  threads([{id:'PRRT_123',isResolved:false}]),
  threads([{id:'PRRT_123'}]),
  threads([],{hasNextPage:true}),
  threads([],{hasPreviousPage:true}),
  {errors:[{message:'partial'}],...threads([])},
  {data:{repository:{pullRequest:{number:40,reviewThreads:{nodes:[],pageInfo:{hasNextPage:false,hasPreviousPage:false}}}}}},
  {data:{repository:{pullRequest:{number:39,reviewThreads:{nodes:null,pageInfo:{hasNextPage:false,hasPreviousPage:false}}}}}},
  {data:{repository:{pullRequest:{number:39,reviewThreads:{nodes:[],pageInfo:{hasNextPage:null,hasPreviousPage:false}}}}}}
 ])denied(()=>validateGitHubReviewThreads(data,prNumber));
});

test('P2 inherited rulesets must be complete; unsupported active rules deny',()=>{
 assert.equal(validateGitHubRulesets([],null).rulesetsCovered,true);
 for(const rulesets of [
  [{id:1,target:'branch',enforcement:'active',name:'more reviews'}],
  [{id:2,target:'branch',enforcement:'evaluate',name:'audit'}],
  [{id:3,target:'branch',enforcement:'unknown',name:'future'}],
  [{id:4,target:'branch',name:'missing state'}],
  null,{},new Array(100).fill({id:1,enforcement:'disabled'})
 ])denied(()=>validateGitHubRulesets(rulesets,null));
 denied(()=>validateGitHubRulesets([], '<https://api.github.com/...>; rel="next"'));
 denied(()=>validateGitHubRulesets([], '<https://api.github.com/...>; rel="prev"'));
 assert.equal(validateGitHubRulesets([{id:8,enforcement:'disabled',target:'branch',name:'off'}],null).rulesetsCovered,true);
});

test('Codex P2: pinned CI explicitly overrides repository npm shell',()=>{
 const ci=readFileSync(new URL('../.github/workflows/ci.yml',import.meta.url),'utf8');
 assert.ok(ci.includes('run: npm --script-shell=/bin/sh run check'));
 assert.doesNotMatch(ci,/run: npm run check/);
});

test('Codex P2: reject .npmrc in authenticated exact HEAD or BASE tree',()=>{
 const sha='a'.repeat(40),treeSha='b'.repeat(40);
 const commit={sha,tree:{sha:treeSha}};
 const good={sha:treeSha,truncated:false,tree:[
   {path:'package.json',type:'blob',sha:'c'.repeat(40)},
   {path:'tests',type:'tree',sha:'d'.repeat(40)},
   {path:'tests/example.mjs',type:'blob',sha:'e'.repeat(40)}
 ]};
 assert.equal(validateNoNpmConfigGitTree({
   head:sha,commit,tree:good}).npmConfigurationAbsent,true);
 for(const patch of [
   {tree:{...good,tree:[...good.tree,{path:'.npmrc',type:'blob',sha:'f'.repeat(40)}]}},
   {tree:{...good,tree:[...good.tree,{path:'nested/.npmrc',type:'blob',sha:'f'.repeat(40)}]}},
   {tree:{...good,tree:[...good.tree,{path:'nested/.NPMRC',type:'blob',sha:'f'.repeat(40)}]}},
   {tree:{...good,truncated:true}},
   {tree:{...good,truncated:undefined}},
   {tree:{...good,sha:'0'.repeat(40)}},
   {tree:{...good,tree:[]}},
   {tree:{...good,tree:[{path:'a',type:'blob',sha:'short'}]}},
   {tree:{...good,tree:[{path:'a/../.npmrc',type:'blob',sha:'f'.repeat(40)}]}},
   {head:'0'.repeat(40)},
   {commit:{...commit,sha:'0'.repeat(40)}},
   {commit:{...commit,tree:{sha:'0'.repeat(40)}}},
   {commit:null},{tree:null}
 ])denied(()=>validateNoNpmConfigGitTree({
   head:sha,commit,tree:good,...patch
 }));
});
