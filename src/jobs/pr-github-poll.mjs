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
 // Verify trusted CI identity, immutable check machinery and executed check.
 // Pinned blob IDs were independently read from protected main a152f920.
 const required=runs.workflow_runs.filter(x=>x.head_sha===sha &&
   x.event==='pull_request' && x.name==='CI' && Number.isSafeInteger(x.id) && x.id>0 &&
   x.workflow_id===402358309 && x.path==='.github/workflows/ci.yml');
 const newest=required.sort((a,b)=>b.id-a.id)[0];
 let passed=null;
 if(newest?.status==='completed' && newest.conclusion==='success'){
  try{
   const pinned=[
    ['.github/workflows/ci.yml','35bbe77dcb0e3dade4f75ee0ad28f1147fe46a7e'],
    ['package.json','031a2750f5949d71909f29390bbef052bb533045'],
    ['scripts/check-privacy.mjs','4b9898dc504dc35d30160473204eb246f3b5ecdc']
   ];
   let controlFilesTrusted=true;
   for(const [path,expectedBlob] of pinned){
    const info=await get('/contents/'+path+'?ref='+sha);
    if(info?.type!=='file'||info.sha!==expectedBlob){controlFilesTrusted=false;break;}
   }
   if(controlFilesTrusted){
    const jobs=await get('/actions/runs/'+newest.id+'/jobs?per_page=100');
    const job=Array.isArray(jobs?.jobs)&&jobs.jobs.length===1&&jobs.total_count===1?jobs.jobs[0]:null;
    const check=Array.isArray(job?.steps)?job.steps.filter(s=>s.name==='Run npm run check'):[];
    if(job?.name==='bootstrap'&&job.status==='completed'&&job.conclusion==='success'&&
       check.length===1&&check[0].status==='completed'&&check[0].conclusion==='success')
      passed=newest;
   }
  }catch{} // Missing or ambiguous proof stays blocked.
 }
 recordPrGate(db,{prKey,headSha:sha,gate:'ci',verdict:passed?'passed':'blocked',
  evidenceId:passed?'github-actions-'+passed.id:'github-ci-provenance-unverified'});
 let next=prNextAction(db,{prKey,observedSha:sha});
 if(next.gate==='independent_review' || next.action==='request_guarded_merge' || next.gate==='security' || next.gate==='private_sse' || next.gate==='pc' || next.gate==='galaxy'){
  // GitHub caps each reviews response at 100. A partial or ambiguous history
  // cannot establish the most recent state of an independent reviewer.
  const reviews=[];
  let historyComplete=false;
  try{
   for(let page=1;page<=10;page++){
    const batch=await get('/pulls/'+number+'/reviews?per_page=100&page='+page);
    if(!Array.isArray(batch)||batch.length>100||batch.some(x=>!Number.isSafeInteger(x?.id)||
      x.id<1||typeof x?.user?.login!=='string'||!['APPROVED','CHANGES_REQUESTED','DISMISSED','COMMENTED','PENDING'].includes(x.state)))
      throw Error('unverifiable PR review page');
    reviews.push(...batch);
    if(batch.length<100){historyComplete=true;break;}
   }
   if(!historyComplete)throw Error('GitHub PR review history exceeds bounded pagination');
  }catch{
   // A network, format or upper-bound error must revoke any cached approval.
   recordPrGate(db,{prKey,headSha:sha,gate:'independent_review',verdict:'blocked',
    evidenceId:'github-review-history-incomplete'});
   return {changed,headSha:sha,...prNextAction(db,{prKey,observedSha:sha})};
  }
  // COMMENTED and PENDING do not withdraw an effective decision; use actual
  // submission chronology rather than creation IDs when timestamps are present.
  const latestByReviewer=new Map();
  for(const review of reviews){
   const login=review.user?.login;
   if(login===pr.user?.login||!['APPROVED','CHANGES_REQUESTED','DISMISSED'].includes(review.state))continue;
   const prev=latestByReviewer.get(login);
   const ta=Date.parse(review.submitted_at||''),tb=Date.parse(prev?.submitted_at||'');
   const newer=prev&&(Number.isFinite(ta)&&Number.isFinite(tb)?
    ta>tb||(ta===tb&&review.id>prev.id):review.id>prev.id);
   if(!prev||newer)latestByReviewer.set(login,review);
  }
  // Examine a bounded set of APPROVED reviewers rather than treating the first
  // public approval as authoritative; an outsider cannot shadow an eligible actor.
  const approvals=[...latestByReviewer.values()].filter(x=>x.state==='APPROVED' && x.commit_id===sha);
  let eligible=null;
  for(const approval of approvals.slice(0,10)){
   if(!/^[A-Za-z0-9-]{1,39}$/.test(approval.user.login))continue;
   try{
    const permission=await get('/collaborators/'+encodeURIComponent(approval.user.login)+'/permission');
    if(permission?.user?.login?.toLowerCase()===approval.user.login.toLowerCase() &&
       ['write','maintain','admin'].includes(permission.permission)){
     eligible=approval;break;
    }
   }catch{} // Permission lookup errors stay blocked, not treated as approval.
  }
  recordPrGate(db,{prKey,headSha:sha,gate:'independent_review',verdict:eligible?'passed':'blocked',evidenceId:eligible?'github-review-'+eligible.id:'github-review-not-eligible-or-current'});
  next=prNextAction(db,{prKey,observedSha:sha});
 }
 return {changed,headSha:sha,...next};
}
