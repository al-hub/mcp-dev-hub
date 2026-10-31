const IDENTIFIER=/^[a-zA-Z0-9](?:[a-zA-Z0-9_.-]{0,98}[a-zA-Z0-9])?$/;
const api='https://api.github.com';
function valid(owner,repo){
  if(!IDENTIFIER.test(owner)||!IDENTIFIER.test(repo)||owner.includes('..')||repo.includes('..'))throw Error('invalid repository');
}
function link(value){return typeof value==='string'&&/^https:\/\/github\.com\/[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+\//.test(value)?value:null;}
function entry(item){return {number:item.number,title:String(item.title||'').slice(0,160),state:item.state==='closed'?'closed':'open',url:link(item.html_url)};}
export function createGithubStatusReader({fetchImpl=fetch,token}={}){
  return async function read({owner,repo}){
    valid(owner,repo);
    const base=`${api}/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}`;
    const headers={'Accept':'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28'};
    if(token)headers.Authorization=`Bearer ${token}`;
    async function get(path){
      let response;
      try{response=await fetchImpl(base+path,{headers,signal:AbortSignal.timeout(10000)});}
      catch{throw Error('GitHub status unavailable');}
      if(!response.ok)throw Error('GitHub status unavailable');
      return response.json();
    }
    const issues=await get('/issues?state=all&per_page=50');
    const pulls=await get('/pulls?state=all&per_page=50');
    const runs=await get('/actions/runs?per_page=30');
    return {
      repository:`${owner}/${repo}`,
      fetchedAt:new Date().toISOString(),
      issues:issues.filter(x=>!x.pull_request).map(entry),
      pullRequests:pulls.map(x=>({...entry(x),merged:x.merged_at!=null,headSha:typeof x.head?.sha==='string'?x.head.sha.slice(0,40):null})),
      ci:(runs.workflow_runs||[]).map(x=>({name:String(x.name||'').slice(0,100),status:x.status,conclusion:x.conclusion,url:link(x.html_url)}))
    };
  };
}
