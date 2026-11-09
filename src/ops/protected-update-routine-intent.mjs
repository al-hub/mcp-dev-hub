// #35 untrusted Worker input for a routine update: DATA ONLY.
// These fields cannot grant root, sign approval, choose roles or pass CI.
import {validateProposedProtectedUpdate}
  from './protected-update-manifest.mjs';
const KEYS=['version','repository','prNumber','head','base','ciRunId',
 'operationId','manifestJson','reviewJson','reviewSignatureBase64'];
const SHA=/^[a-f0-9]{40}$/,ID=/^[a-f0-9]{32}$/,
 B64=/^[A-Za-z0-9+/]{86}==$/;
const deny=()=>{throw Error('protected_routine_intent_denied');};
export function parseProtectedRoutineIntent(raw){
 if(typeof raw!=='string'||Buffer.byteLength(raw,'utf8')>9000)deny();
 let x;try{x=JSON.parse(raw);}catch{deny();}
 if(!x||typeof x!=='object'||Array.isArray(x)||
    Object.keys(x).length!==KEYS.length||
    !KEYS.every(k=>Object.hasOwn(x,k))||
    JSON.stringify(x)!==raw||x.version!==2||
    x.repository!=='al-hub/mcp-dev-hub'||x.prNumber!==39||
    !SHA.test(x.head||'')||!SHA.test(x.base||'')||x.head===x.base||
    !Number.isSafeInteger(x.ciRunId)||x.ciRunId<=0||
    !ID.test(x.operationId||'')||
    typeof x.manifestJson!=='string'||
    Buffer.byteLength(x.manifestJson,'utf8')>4096||
    typeof x.reviewJson!=='string'||
    Buffer.byteLength(x.reviewJson,'utf8')>2048||
    !B64.test(x.reviewSignatureBase64||''))deny();
 try{
   const manifest=validateProposedProtectedUpdate(x.manifestJson,{
     verifiedCommit:x.head
   });
   if(manifest.commit!==x.head||manifest.files.length!==2)deny();
 }catch{deny();}
 return Object.freeze({...x});
}
