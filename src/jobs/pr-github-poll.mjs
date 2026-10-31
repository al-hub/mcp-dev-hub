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
 // CI is the required workflow for this repository. Do not accept an unrelated success.
 const required=runs.workflow_runs.filter(x=>x.head_sha===sha && x.event==='pull_request' && x.name==='CI' && Number.isSafeInteger(x.id));
 const newest=required.sort((a,b)=>b.id-a.id)[0];
 const passed=newest?.status==='completed' && newest.conclusion==='success' ? newest : null;
 recordPrGate(db,{prKey,headSha:sha,gate:'ci',verdict:passed?'passed':'blocked',evidenceId:passed?'github-actions-'+passed.id:'github-ci-not-current'});
 let next=prNextAction(db,{prKey,observedSha:sha});
 if(next.gate==='independent_review' || next.action==='request_guarded_merge' || next.gate==='security' || next.gate==='private_sse' || next.gate==='pc' || next.gate==='galaxy'){
  const reviews=await get('/pulls/'+number+'/reviews?per_page=100');
  if(!Array.isArray(reviews))throw Error('unverifiable PR review state');
  // Only the latest review per independent reviewer counts; stale SHA or dismissed reviews do not.
  const latestByReviewer=new Map();
  for(const review of reviews){
   const login=review.user?.login;
   if(typeof login==='string' && login!==pr.user?.login && Number.isSafeInteger(review.id)){
    const prev=latestByReviewer.get(login);
    if(!prev||review.id>prev.id)latestByReviewer.set(login,review);
   }
  }
  const approved=[...latestByReviewer.values()].find(x=>x.state==='APPROVED' && x.commit_id===sha);
  recordPrGate(db,{prKey,headSha:sha,gate:'independent_review',verdict:approved?'passed':'blocked',evidenceId:approved?'github-review-'+approved.id:'github-review-not-current'});
  next=prNextAction(db,{prKey,observedSha:sha});
 }
 return {changed,headSha:sha,...next};
}
