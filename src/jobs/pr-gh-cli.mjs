import {execFileSync} from 'node:child_process';
import {pollPrGithub} from './pr-github-poll.mjs';

// Use GitHub CLI's existing authenticated credential store without exporting its token.
// Only read GitHub REST URLs validated by the PR poller.
export async function pollPrWithGh({db,prKey,runner=execFileSync}){
 const fetchImpl=async (url)=>{
  const u=new URL(url);
  if(u.origin!=='https://api.github.com'||!/^\/repos\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+\/(pulls\/[1-9][0-9]*(\/reviews)?|actions\/runs)$/.test(u.pathname))
   throw Error('unapproved GitHub API path');
  let value;
  try{value=JSON.parse(runner('gh',['api',u.pathname+u.search,'--method','GET'],{encoding:'utf8',timeout:15000,stdio:['ignore','pipe','ignore'],maxBuffer:1000000}));}
  catch{throw Error('authenticated GitHub API unavailable');}
  return {ok:true,json:async()=>value};
 };
 return pollPrGithub({db,prKey,token:'github-cli-authenticated-credential',fetchImpl});
}
