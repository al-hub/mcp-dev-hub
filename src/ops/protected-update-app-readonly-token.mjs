// #35: pinned existing GitHub App, exact-repository read-only evidence tokens.
// Source contract only. A root-controlled caller must own the App PEM and
// must never persist an unrestricted installation token or print a bearer.
import {createPrivateKey,createSign} from 'node:crypto';
export const APP_ID=5576601;
export const REPOSITORY_ID=1440361577;
export const APP_SLUG='mcp-dev-hub-ai-reviewer';
export const READ_PERMISSIONS=Object.freeze({
 administration:'read',actions:'read',checks:'read',
 statuses:'read',contents:'read',pull_requests:'read'
});
const fail=()=>{throw Error('protected_app_readonly_evidence_denied');};
const object=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
const id=x=>Number.isSafeInteger(x)&&x>0;
export function verifyExistingAppAndInstallation(app,installation){
 if(!object(app)||app.id!==APP_ID||app.slug!==APP_SLUG||
    !object(installation)||!id(installation.id)||
    installation.app_id!==APP_ID||installation.app_slug!==APP_SLUG||
    installation.account?.login!=='al-hub'||
    installation.suspended_at!==null)fail();
 for(const name of Object.keys(READ_PERMISSIONS)){
  if(!['read','write'].includes(app.permissions?.[name])||
     !['read','write'].includes(installation.permissions?.[name]))fail();
 }
 return Object.freeze({installationId:installation.id,ready:true});
}
export function createExistingAppJWT(pem,nowMs=Date.now()){
 if(typeof pem!=='string'||pem.length<128||pem.length>16384||
    !Number.isSafeInteger(nowMs)||nowMs<=0)fail();
 let key;
 try{key=createPrivateKey(pem);}catch{fail();}
 if(key.asymmetricKeyType!=='rsa')fail();
 const enc=x=>Buffer.from(JSON.stringify(x)).toString('base64url');
 const now=Math.floor(nowMs/1000);
 const data=enc({alg:'RS256',typ:'JWT'})+'.'+enc({
  iat:now-60,exp:now+480,iss:String(APP_ID)
 });
 return data+'.'+createSign('RSA-SHA256').update(data).end()
   .sign(key,'base64url');
}
export function verifyScopedReadOnlyToken(response,nowMs=Date.now()){
 if(!object(response)||typeof response.token!=='string'||
    !/^ghs_[A-Za-z0-9_]{20,4090}$/.test(response.token)||
    !object(response.permissions)||
    response.repository_selection!=='selected')fail();
 const actual=Object.keys(response.permissions).sort();
 const expected=[...Object.keys(READ_PERMISSIONS),'metadata'].sort();
 if(actual.join(',')!==expected.join(','))fail();
 for(const [name,grant] of Object.entries(READ_PERMISSIONS)){
  if(response.permissions[name]!==grant)fail();
 }
 if(response.permissions.metadata!=='read')fail();
 if(Object.hasOwn(response,'repositories')&&
    (!Array.isArray(response.repositories)||
      response.repositories.length!==1||
      response.repositories[0]?.id!==REPOSITORY_ID))fail();
 if(typeof response.expires_at!=='string'||!
    Number.isSafeInteger(nowMs))fail();
 const expiresAtMs=Date.parse(response.expires_at);
 if(!Number.isFinite(expiresAtMs)||
    expiresAtMs-nowMs<10*60_000||
    expiresAtMs-nowMs>65*60_000)fail();
 return Object.freeze({
  token:response.token,expiresAt:response.expires_at,
  expiresAtMs,permissions:'strict_read_only',singleRepository:true
 });
}
export async function requestScopedReadOnlyToken({
 appJwt,installationId,post,nowMs=Date.now()
}={}){
 if(typeof appJwt!=='string'||appJwt.length<40||
    !id(installationId)||typeof post!=='function')fail();
 const res=await post({
  method:'POST',
  path:'/app/installations/'+installationId+'/access_tokens',
  authorization:appJwt,
  body:{
   repository_ids:[REPOSITORY_ID],
   permissions:READ_PERMISSIONS
  }
 });
 if(res?.status!==201)fail();
 return verifyScopedReadOnlyToken(res.body,nowMs);
}
