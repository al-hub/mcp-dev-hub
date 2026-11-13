import {test} from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync} from 'node:crypto';
import {
 APP_ID,REPOSITORY_ID,APP_SLUG,READ_PERMISSIONS,
 verifyExistingAppAndInstallation,createExistingAppJWT,
 verifyScopedReadOnlyToken,requestScopedReadOnlyToken
} from '../src/ops/protected-update-app-readonly-token.mjs';
const now=1780000000000;
const app={id:APP_ID,slug:APP_SLUG,
 permissions:{...READ_PERMISSIONS,contents:'write',pull_requests:'write'}};
const installation={id:177759528,app_id:APP_ID,app_slug:APP_SLUG,
 account:{login:'al-hub'},suspended_at:null,
 permissions:{...app.permissions}};
const access=()=>({
 token:'ghs_'+('A'.repeat(52)),
 expires_at:new Date(now+50*60000).toISOString(),
 repository_selection:'selected',repositories:[{id:REPOSITORY_ID}],
 permissions:{...READ_PERMISSIONS,metadata:'read'}
});
test('registered and installed rights must both cover live evidence APIs',()=>{
 assert.equal(verifyExistingAppAndInstallation(app,installation).ready,true);
 for(const n of Object.keys(READ_PERMISSIONS)){
  assert.throws(()=>verifyExistingAppAndInstallation(app,{
   ...installation,permissions:{...installation.permissions,[n]:'none'}
  }));
 }
 assert.throws(()=>verifyExistingAppAndInstallation(app,{
  ...installation,app_id:1
 }));
 assert.throws(()=>verifyExistingAppAndInstallation(app,{
  ...installation,suspended_at:'2026-01-01T00:00:00Z'
 }));
});
test('App-signed JWT requires the existing RSA key',()=>{
 const {privateKey}=generateKeyPairSync('rsa',{modulusLength:2048});
 const pem=privateKey.export({type:'pkcs8',format:'pem'});
 const jwt=createExistingAppJWT(pem,now);
 const claim=JSON.parse(Buffer.from(jwt.split('.')[1],'base64url'));
 assert.equal(claim.iss,String(APP_ID));
 assert.equal(claim.exp-claim.iat,540);
 assert.throws(()=>createExistingAppJWT('not a PEM',now));
});
test('restricts minted token to selected repository and read-only permissions',()=>{
 assert.equal(verifyScopedReadOnlyToken(access(),now).singleRepository,true);
 for(const n of Object.keys(READ_PERMISSIONS)){
  const x=access();x.permissions[n]='write';
  assert.throws(()=>verifyScopedReadOnlyToken(x,now));
 }
 const extra=access();extra.permissions.workflows='write';
 assert.throws(()=>verifyScopedReadOnlyToken(extra,now));
 const repo=access();repo.repositories=[{id:1}];
 assert.throws(()=>verifyScopedReadOnlyToken(repo,now));
 const all=access();all.repository_selection='all';
 assert.throws(()=>verifyScopedReadOnlyToken(all,now));
 const stale=access();stale.expires_at=new Date(now+1000).toISOString();
 assert.throws(()=>verifyScopedReadOnlyToken(stale,now));
});
test('request pins exact repo and all requested read-only scopes',async()=>{
 const calls=[];
 const result=await requestScopedReadOnlyToken({
  appJwt:'x'.repeat(50),installationId:177759528,nowMs:now,
  post:async req=>{calls.push(req);return {status:201,body:access()}}
 });
 assert.equal(result.permissions,'strict_read_only');
 assert.deepEqual(calls[0].body.permissions,READ_PERMISSIONS);
 assert.deepEqual(calls[0].body.repository_ids,[REPOSITORY_ID]);
 await assert.rejects(requestScopedReadOnlyToken({
  appJwt:'x'.repeat(50),installationId:177759528,nowMs:now,
  post:async()=>({status:403,body:{}})
 }));
});
