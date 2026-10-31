import {trackPr,recordPrGate,prNextAction} from './pr-automation.mjs';

// Trusted GitHub API polling is the private, outbound-only event source until a signed
// webhook receiver is deployed. Nothing is merged or marked reviewed by this adapter.
export async function pollPrGithub({db,prKey,token,fetchImpl=fetch}){
 const match=/^([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)#([1-9][0-9]*)$/.exec(prKey||'');
 if(!match || typeof token!=='string' || token.length<20)throw Error('PR monitor configuration missing');
 const [,owner,repo,number]=match;
 const base='https://api.github.com/repos/'+encodeURIComponent(owner)+'/'+encodeURIComponent(repo);
 const headers={'Accept':'application/vnd.github+json','Authorization':'Bearer '+token,'X-GitHub-Api-Version':'2022-11-28'};
 async function get(path){
  const res=await fetchImpl(base+path,{headers,signal:AbortSignal.timeout(12000)});
  if(!res.ok)throw Error('GitHub PR status unavailable');
  return res.json();
 }
 const pr=await get('/pulls/'+number);
 if(pr.number!==Number(number)||!pr.head||!pr.head.sha||!/^[a-f0-9]{40}$/.test(pr.head.sha))
  throw Error('unverifiable PR state');
 if(pr.state!=='open')return {state:'closed',action:'reconcile'};
 const sha=pr.head.sha;
 const changed=trackPr(db,{prKey,headSha:sha}).changed;
 const runs=await get('/actions/runs?head_sha='+sha+'&per_page=30');
 if(!Array.isArray(runs.workflow_runs))throw Error('unverifiable CI runs');
 const completed=runs.workflow_runs.filter(x=>x.head_sha===sha && x.event==='pull_request' && x.status==='completed' && Number.isSafeInteger(x.id));
 const passed=completed.find(x=>x.conclusion==='success');
 if(passed)recordPrGate(db,{prKey,headSha:sha,gate:'ci',verdict:'passed',evidenceId:'github-actions-'+passed.id});
 return {changed,headSha:sha,...prNextAction(db,{prKey,observedSha:sha})};
}
