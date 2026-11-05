// #35: parse an UNTRUSTED proposed protected-file update manifest.
// This module does NOT grant privilege, verify a GitHub identity, or approve
// execution. A separately installed root-owned verifier must independently
// authenticate the exact GitHub commit, CI, reviewer and content bytes.
export const PROTECTED_REPOSITORY='al-hub/mcp-dev-hub';
const SHA40=/^[0-9a-f]{40}$/;
const SHA256=/^[0-9a-f]{64}$/;
const BUNDLE=Object.freeze({
 'ai-github-canary-policy.mjs': 256*1024,
 'ai-github-canary.mjs': 256*1024
});
const hasKeys=(value,keys)=>{
 if(value===null||typeof value!=='object'||Array.isArray(value))return false;
 return Object.keys(value).sort().join('\0')===keys.slice().sort().join('\0');
};
export function validateProposedProtectedUpdate(rawJson,{verifiedCommit}={}){
 // An inert JSON text boundary prevents accessor/Proxy execution inside a
 // future privileged verifier. No reviver, eval, JSON-like object or JS code.
 if(typeof rawJson!=='string'||Buffer.byteLength(rawJson,'utf8')>4096)
  throw Error('invalid_update_json_input');
 let value;
 try{value=JSON.parse(rawJson);}catch{throw Error('invalid_update_json_input');}
 // verifiedCommit MUST come from a separately authenticated root-owned
 // verifier; it is not an authorization token and does not prove code safety.
 if(typeof verifiedCommit!=='string'||!SHA40.test(verifiedCommit))
  throw Error('trusted_commit_missing');
 if(!hasKeys(value,['version','repository','commit','bundle','files'])||
    value.version!==1||
    value.repository!==PROTECTED_REPOSITORY||
    value.bundle!=='controller-pair'||
    !SHA40.test(value.commit||'')||value.commit!==verifiedCommit)
  throw Error('invalid_protected_update_manifest');
 if(!Array.isArray(value.files)||value.files.length!==2)
  throw Error('invalid_protected_update_file_count');
 const seen=new Set();
 const parsed=[];
 for(const file of value.files){
  if(!hasKeys(file,['name','sha256','bytes'])||
     typeof file.name!=='string'||
     !Object.hasOwn(BUNDLE,file.name)||seen.has(file.name)||
     typeof file.sha256!=='string'||!SHA256.test(file.sha256)||
     !Number.isSafeInteger(file.bytes)||
     file.bytes<1||file.bytes>BUNDLE[file.name])
   throw Error('invalid_protected_update_file');
  seen.add(file.name);
  parsed.push(Object.freeze({name:file.name,sha256:file.sha256,bytes:file.bytes}));
 }
 if(seen.size!==Object.keys(BUNDLE).length)
  throw Error('incomplete_controller_pair');
 parsed.sort((a,b)=>a.name.localeCompare(b.name,'en'));
 return Object.freeze({
  repository:PROTECTED_REPOSITORY,
  commit:verifiedCommit,
  bundle:'controller-pair',
  files:Object.freeze(parsed)
 });
}
