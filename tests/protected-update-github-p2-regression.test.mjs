import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {
  PINNED_CI_SOURCES,validatePinnedCiSources,
  validateGitHubReviewThreads,validateGitHubRulesets
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
