import {execFileSync} from 'node:child_process';
import {pollPrGithub} from './pr-github-poll.mjs';

// Use GitHub CLI's existing authenticated credential store without exporting its token.
// Only read GitHub REST URLs validated by the PR poller.
export async function pollPrWithGh({db,prKey,runner=execFileSync}){
 const fetchImpl=async (url)=>{
  const u=new URL(url);
  if(u.origin!=='https://api.github.com'||!/^\/repos\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+\/(pulls\/[1-9][0-9]*(\/reviews)?|actions\/runs(\/[1-9][0-9]*\/jobs)?|contents\/(\.github\/workflows\/ci\.yml|package\.json|scripts\/check-privacy\.mjs)|collaborators\/[A-Za-z0-9-]+\/permission)$/.test(u.pathname))
   throw Error('unapproved GitHub API path');
  if(u.pathname.includes('/contents/')&&!/^\?ref=[a-f0-9]{40}$/.test(u.search))
   throw Error('unapproved GitHub content revision');
  if(u.pathname.endsWith('/jobs')&&u.search!=='?per_page=100')
   throw Error('unapproved GitHub jobs query');
  let value;
  try{
   const home=process.env.HOME;
   if(typeof home!=='string'||!home.startsWith('/')||home.includes('\0')||home.length>4096)
    throw Error('untrusted GitHub CLI home');
   const env={PATH:'/usr/bin:/bin',HOME:home,LANG:'C.UTF-8',
    GH_HOST:'github.com',GH_PROMPT_DISABLED:'1'};
   value=JSON.parse(runner('/usr/bin/gh',['api',u.pathname+u.search,'--method','GET'],
    {encoding:'utf8',timeout:15000,stdio:['ignore','pipe','ignore'],maxBuffer:1000000,
     cwd:'/',env}));
  }
  catch{throw Error('authenticated GitHub API unavailable');}
  return {ok:true,json:async()=>value};
 };
 return pollPrGithub({db,prKey,token:'github-cli-authenticated-credential',fetchImpl});
}
