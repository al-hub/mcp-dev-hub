import {fileURLToPath} from 'node:url';
import {resolve} from 'node:path';
import {readPrivateKey,createScopedAppClient} from '../src/jobs/github-app-review-publisher.mjs';

// Explicit, separately invoked App-authentication and identity preflight only.
// No review submission is exposed here. Secrets, tokens and errors never print.
// Production credentials must be provisioned in a trusted, separate execution
// context, not inside the development Worker or untrusted PR checkout.
const ACTOR='mcp-dev-hub-ai-reviewer[bot]';
const REPO_ID=1440361577;
const HEAD=/^[a-f0-9]{40}$/;
const NAMES=[
 'MCP_DEV_HUB_REVIEWER_APP_ID',
 'MCP_DEV_HUB_REVIEWER_APP_INSTALLATION_ID',
 'MCP_DEV_HUB_REVIEWER_APP_PRIVATE_KEY_FILE',
 'MCP_DEV_HUB_REVIEWER_EXPECTED_HEAD_SHA'
];
const positive=(x)=>/^[1-9][0-9]{0,15}$/.test(x||'')&&Number.isSafeInteger(Number(x));

export async function checkReviewerConnection({
 env=process.env,readKey=readPrivateKey,createClient=createScopedAppClient
}={}){
 const missing=NAMES.filter(k=>typeof env[k]!=='string'||env[k].length===0);
 if(missing.length)return {status:'blocked',reason:'configuration_missing',missing};
 if(!positive(env.MCP_DEV_HUB_REVIEWER_APP_ID)||
    !positive(env.MCP_DEV_HUB_REVIEWER_APP_INSTALLATION_ID)||
    !env.MCP_DEV_HUB_REVIEWER_APP_PRIVATE_KEY_FILE.startsWith('/')||
    !HEAD.test(env.MCP_DEV_HUB_REVIEWER_EXPECTED_HEAD_SHA)){
  return {status:'blocked',reason:'configuration_invalid'};
 }
 try{
  const key=readKey(env.MCP_DEV_HUB_REVIEWER_APP_PRIVATE_KEY_FILE);
  const {api,actor}=await createClient({
   appId:Number(env.MCP_DEV_HUB_REVIEWER_APP_ID),
   installationId:Number(env.MCP_DEV_HUB_REVIEWER_APP_INSTALLATION_ID),
   repositoryId:REPO_ID,key
  });
  if(actor!==ACTOR)return {status:'blocked',reason:'app_identity_or_pr_unverified'};
  const pr=await api('GET','/repos/al-hub/mcp-dev-hub/pulls/17');
  if(pr?.number!==17||pr.state!=='open'||
     pr.head?.sha!==env.MCP_DEV_HUB_REVIEWER_EXPECTED_HEAD_SHA||
     pr.base?.ref!=='main'||pr.user?.login!=='al-hub'||
     pr.user?.login===actor){
   return {status:'blocked',reason:'app_identity_or_pr_unverified'};
  }
  return {status:'ready',actor,headSha:pr.head.sha,prNumber:17};
 }catch{
  return {status:'blocked',reason:'app_authentication_or_scope_unverified'};
 }
}

if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 if(process.argv.length!==2){
  process.stdout.write(JSON.stringify({status:'blocked',reason:'unsupported_arguments'})+'\n');
  process.exitCode=78;
 }else{
  const outcome=await checkReviewerConnection();
  process.stdout.write(JSON.stringify(outcome)+'\n');
  if(outcome.status!=='ready')process.exitCode=78;
 }
}
