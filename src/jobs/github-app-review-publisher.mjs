import {createSign} from 'node:crypto';
import {lstatSync,readFileSync,realpathSync} from 'node:fs';

// GitHub App publisher for one explicitly authorized repository.
// AI output is never an approval by itself. The caller must supply a trusted
// Worker evidence verifier and an independently authenticated App client.
const SHA=/^[a-f0-9]{40}$/;
const REPO='al-hub/mcp-dev-hub';
const GATES=['ci','security','private_sse','pc','galaxy'];
const fail=(message)=>{throw Error(message);};
export function validateReviewEvidence({headSha,evidence,verifyEvidence}){
 if(!SHA.test(headSha)||typeof verifyEvidence!=='function')fail('trusted evidence verifier required');
 if(!evidence||evidence.headSha!==headSha||evidence.authorAgent!=='agy'||
   evidence.reviewerAgent!=='codex'||evidence.verdict!=='passed'||
   evidence.reviewReadonly!==true||evidence.reviewIsolated!==true||
   evidence.exitCode!==0||typeof evidence.evidenceId!=='string'||
   !/^verified-[a-z0-9-]{6,100}$/.test(evidence.evidenceId))fail('independent review evidence unavailable');
 for(const gate of GATES){
  const value=evidence.gates?.[gate];
  if(value?.headSha!==headSha||value?.verdict!=='passed'||
     typeof value?.evidenceId!=='string'||value.evidenceId.length<4)fail('acceptance gate incomplete');
 }
 return verifyEvidence(evidence)===true || fail('unverified independent review provenance');
}
export function createAppJwt({appId,privateKey,now=Math.floor(Date.now()/1000)}){
 if(!Number.isSafeInteger(appId)||appId<1||typeof privateKey!=='string'||!privateKey.includes('PRIVATE KEY')||
    !Number.isSafeInteger(now))fail('invalid GitHub App configuration');
 const encoded=o=>Buffer.from(JSON.stringify(o)).toString('base64url');
 const value=encoded({alg:'RS256',typ:'JWT'})+'.'+encoded({iat:now-60,exp:now+540,iss:String(appId)});
 const signature=createSign('RSA-SHA256').update(value).end().sign(privateKey,'base64url');
 return value+'.'+signature;
}
export function readPrivateKey(path){
 if(typeof path!=='string'||!path.startsWith('/')||path.includes('/../'))fail('invalid private key path');
 const st=lstatSync(path);
 if(!st.isFile()||st.isSymbolicLink()||(st.mode&0o077)!==0||
    (typeof process.getuid==='function'&&st.uid!==process.getuid()))fail('insecure private key permissions');
 const real=realpathSync(path);
 if(real!==path)fail('private key must be a direct regular file');
 return readFileSync(path,'utf8');
}
export async function createScopedAppClient({appId,installationId,repositoryId,key,fetchImpl=fetch}){
 if(!Number.isSafeInteger(installationId)||installationId<1||
    !Number.isSafeInteger(repositoryId)||repositoryId<1)fail('invalid App installation');
 const jwt=createAppJwt({appId,privateKey:key});
 const call=async(method,path,body,token)=>{
  const response=await fetchImpl('https://api.github.com'+path,{
   method,headers:{Accept:'application/vnd.github+json',
    Authorization:'Bearer '+token,'X-GitHub-Api-Version':'2022-11-28',
    ...(body?{'Content-Type':'application/json'}:{})},
   ...(body?{body:JSON.stringify(body)}:{}),signal:AbortSignal.timeout(12000)
  });
  if(!response.ok)fail('GitHub App request denied or unavailable');
  return response.json();
 };
 const app=await call('GET','/app',null,jwt);
 if(app.id!==appId||!/^[-a-z0-9]+$/.test(app.slug||''))fail('unexpected GitHub App identity');
 const access=await call('POST','/app/installations/'+installationId+'/access_tokens',
   {repository_ids:[repositoryId],permissions:{pull_requests:'write'}},jwt);
 if(typeof access.token!=='string'||access.token.length<20||
    access.permissions?.pull_requests!=='write')fail('insufficient scoped installation token');
 const scoped=async (method,path,body)=>{
  if(!/^\/repos\/al-hub\/mcp-dev-hub\/(pulls\/[1-9][0-9]*(\/reviews(\?per_page=100)?)?|branches\/main\/protection|actions\/runs\?head_sha=[a-f0-9]{40}&per_page=30)$/.test(path)
     && path!=='/graphql')fail('unapproved GitHub App API path');
  return call(method,path,body,access.token);
 };
 const repos=await scoped('GET','/repos/al-hub/mcp-dev-hub/pulls/17');
 if(repos.base?.repo?.id!==undefined && repos.base.repo.id!==repositoryId)fail('repository identity mismatch');
 return {api:scoped,actor:app.slug+'[bot]'};
}
export async function publishIndependentApproval({
 api,actor,headSha,prNumber=17,evidence,verifyEvidence
}){
 if(typeof api!=='function'||typeof actor!=='string'||!/^[-a-z0-9]+\[bot\]$/.test(actor)||
    prNumber!==17||!SHA.test(headSha))fail('review publisher scope denied');
 validateReviewEvidence({headSha,evidence,verifyEvidence});
 const prefix='/repos/'+REPO;
 const pr=await api('GET',prefix+'/pulls/'+prNumber);
 if(pr.number!==prNumber||pr.state!=='open'||pr.head?.sha!==headSha||
    pr.base?.ref!=='main'||pr.user?.login===actor)fail('stale or self-authored pull request');
 const protection=await api('GET',prefix+'/branches/main/protection');
 if(protection.enforce_admins?.enabled!==true||
    !(protection.required_pull_request_reviews?.required_approving_review_count>=1)||
    protection.required_pull_request_reviews?.dismiss_stale_reviews!==true)fail('required review protection not active');
 const contexts=protection.required_status_checks?.contexts??[];
 if(!contexts.includes('bootstrap'))fail('required GitHub CI protection missing');
 const runs=await api('GET',prefix+'/actions/runs?head_sha='+headSha+'&per_page=30');
 const matching=(runs.workflow_runs??[]).filter(x=>x.head_sha===headSha&&
    x.event==='pull_request'&&x.name==='CI'&&Number.isSafeInteger(x.id))
    .sort((a,b)=>b.id-a.id);
 if(matching[0]?.status!=='completed'||matching[0].conclusion!=='success')fail('current SHA CI not successful');
 const reviews=await api('GET',prefix+'/pulls/'+prNumber+'/reviews?per_page=100');
 if(!Array.isArray(reviews)||reviews.length>=100)fail('incomplete GitHub reviews listing');
 const own=reviews.filter(x=>x.user?.login===actor).sort((a,b)=>b.id-a.id)[0];
 if(own && (own.state!=='APPROVED'||own.commit_id!==headSha))fail('existing Bot review needs reconciliation');
 let review=own;
 if(!review){
  // Never replay an uncertain POST. The caller must first reconcile the live reviews.
  review=await api('POST',prefix+'/pulls/'+prNumber+'/reviews',{
   commit_id:headSha,event:'APPROVE',
   body:'AI-assisted independent Codex technical review (not a human review). Evidence: '+evidence.evidenceId
  });
 }
 const after=await api('GET',prefix+'/pulls/'+prNumber+'/reviews?per_page=100');
 const confirmed=Array.isArray(after)&&after.some(x=>x.id===review.id&&x.state==='APPROVED'&&
    x.commit_id===headSha&&x.user?.login===actor);
 if(!confirmed)fail('review submission not confirmed; do not retry');
 const query='query($owner:String!,$name:String!,$number:Int!){repository(owner:$owner,name:$name){pullRequest(number:$number){reviewDecision}}}';
 const result=await api('POST','/graphql',{query,variables:{owner:'al-hub',name:'mcp-dev-hub',number:17}});
 if(result.data?.repository?.pullRequest?.reviewDecision!=='APPROVED')
  fail('GitHub does not confirm required approval eligibility');
 return {state:'approved',reviewId:review.id,headSha,actor};
}
