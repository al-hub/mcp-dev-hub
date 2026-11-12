// #35 source-only verifier for the FINAL persisted result of a real Codex run.
// This pure module is not a signer: synthetic calls cannot authorize a review.
// Only the separately installed, OS-pinned immutable runner can generate a
// signed receipt after it personally launches Codex and validates its result.
import {createHash} from 'node:crypto';
import {PINNED_CI_SOURCES} from './protected-update-github-evidence.mjs';

const SHA=/^[0-9a-f]{40}$/;
const RUN=/^[0-9a-f]{32}$/;
const deny=()=>{throw Error('protected_codex_terminal_denied');};
const exact=(o,keys)=>o!==null&&typeof o==='object'&&!Array.isArray(o)&&
  Object.keys(o).length===keys.length&&keys.every(k=>Object.hasOwn(o,k));

export function validatePersistedCodexPass({
  raw,head,base,result
}={}){
  // Transport/CLI exit success is NEVER a review verdict.
  if(typeof raw!=='string'||Buffer.byteLength(raw,'utf8')<60||
     Buffer.byteLength(raw,'utf8')>2048||
     !SHA.test(head||'')||!SHA.test(base||'')||head===base||
     result?.status!==0||result?.signal!==null||
     result?.error!==undefined||result?.outputOverflow===true)deny();
  const trimmed=raw.trim();
  let parsed;
  try{parsed=JSON.parse(trimmed);}catch{deny();}
  // Require a single, byte-canonical, four-field terminal object. Duplicate
  // keys, Markdown, prefix prose, partial/truncated output and PASS-shaped
  // strings are refused even if the CLI itself exited zero.
  if(!exact(parsed,['verdict','head','base','findings'])||
     JSON.stringify(parsed)!==trimmed||
     parsed.verdict!=='PASS'||parsed.head!==head||
     parsed.base!==base||!Array.isArray(parsed.findings)||
     parsed.findings.length!==0)deny();
  return Object.freeze({
    verdict:'PASS',head,base,
    terminalSha256:createHash('sha256').update(trimmed,'utf8').digest('hex')
  });
}


const REVIEW_INPUT_LIMIT=2*1024*1024;
const HASH=/^[a-f0-9]{64}$/;
const own=(v,keys)=>v!==null&&typeof v==='object'&&!Array.isArray(v)&&
  Object.keys(v).length===keys.length&&keys.every(k=>Object.hasOwn(v,k));
const hash=s=>createHash('sha256').update(s,'utf8').digest('hex');

/** Canonical complete source artifact tied to the OWNER-PINNED immutable
 * package manifest. A Worker can construct a synthetic packet for tests,
 * but only the pinned manifest digest plus fixed installed Codex signer
 * authenticates this review. Never trust an arbitrary text hash.
 */
export function validatePinnedCodexSourceReviewInput({
  raw,head,packDigest
}={}){
 if(typeof raw!=='string'||Buffer.byteLength(raw,'utf8')<100||
    Buffer.byteLength(raw,'utf8')>REVIEW_INPUT_LIMIT||
    !SHA.test(head||'')||!HASH.test(packDigest||''))deny();
 let doc,manifest;
 try{doc=JSON.parse(raw);manifest=JSON.parse(doc.manifestJson);}catch{deny();}
 const routine=Object.hasOwn(doc,'candidateManifestJson')||
   Object.hasOwn(doc,'candidateFiles');
 const docFields=routine
   ?['version','manifestJson','files','candidateManifestJson','candidateFiles']
   :['version','manifestJson','files'];
 if(!own(doc,docFields)||doc.version!==2||
    JSON.stringify(doc)!==raw||
    typeof doc.manifestJson!=='string'||
    Buffer.byteLength(doc.manifestJson,'utf8')>16384||
    !own(manifest,['version','repository','head','installAuthorized',
      'requiredIndependentIssuers','files'])||
    manifest.version!==1||manifest.repository!=='al-hub/mcp-dev-hub'||
    (routine?!SHA.test(manifest.head||''):manifest.head!==head)||
    manifest.installAuthorized!==false||
    JSON.stringify(manifest)!==doc.manifestJson||
    hash(doc.manifestJson)!==packDigest||
    JSON.stringify(manifest.requiredIndependentIssuers)!==
      JSON.stringify(['independent-codex','protected-approval'])||
    !Array.isArray(manifest.files)||manifest.files.length<50||
    manifest.files.length>128||!Array.isArray(doc.files)||
    doc.files.length!==manifest.files.length)deny();
 let total=0;
 const rendered=[];
 const names=new Set();
 for(let i=0;i<manifest.files.length;i++){
  const m=manifest.files[i],f=doc.files[i];
  if(!own(m,['path','bytes','sha256'])||!own(f,['path','content'])||
     typeof m.path!=='string'||!
       /^(?:\.github\/workflows\/ci\.yml|package\.json|(?:scripts|src\/(?:ops|jobs))\/[a-z0-9.-]+\.mjs)$/.test(m.path)||
     names.has(m.path)||f.path!==m.path||
     !Number.isSafeInteger(m.bytes)||m.bytes<1||m.bytes>262144||
     !HASH.test(m.sha256||'')||typeof f.content!=='string')deny();
  const bytes=Buffer.from(f.content,'utf8');
  if(bytes.length!==m.bytes||hash(f.content)!==m.sha256)deny();
  total+=bytes.length;
  if(total>REVIEW_INPUT_LIMIT)deny();
  names.add(m.path);
  rendered.push('### '+m.path+' ('+m.sha256+')\n'+f.content+'\n');
 }
 for(const pin of PINNED_CI_SOURCES)if(!names.has(pin.path))deny();
 let candidateManifestSha256=null;
 if(routine){
  if(typeof doc.candidateManifestJson!=='string'||
     Buffer.byteLength(doc.candidateManifestJson)>4096||
     !Array.isArray(doc.candidateFiles)||doc.candidateFiles.length!==2)deny();
  let candidate;
  try{candidate=JSON.parse(doc.candidateManifestJson);}catch{deny();}
  if(!own(candidate,['version','repository','commit','bundle','files'])||
     JSON.stringify(candidate)!==doc.candidateManifestJson||
     candidate.version!==1||candidate.repository!=='al-hub/mcp-dev-hub'||
     candidate.commit!==head||candidate.bundle!=='controller-pair'||
     !Array.isArray(candidate.files)||candidate.files.length!==2||
     candidate.files[0]?.name!=='ai-github-canary-policy.mjs'||
     candidate.files[1]?.name!=='ai-github-canary.mjs'||
     manifest.head===head)deny();
  for(let i=0;i<2;i++){
   const f=doc.candidateFiles[i],m=candidate.files[i];
   if(!own(f,['name','content'])||
      !own(m,['name','sha256','bytes'])||
      f.name!==m.name||typeof f.content!=='string'||
      !Number.isSafeInteger(m.bytes)||m.bytes<1||
      m.bytes>262144||!HASH.test(m.sha256||'')||
      Buffer.byteLength(f.content,'utf8')!==m.bytes||
      hash(f.content)!==m.sha256)deny();
   total+=m.bytes;
   if(total>REVIEW_INPUT_LIMIT)deny();
   rendered.push('### PROPOSED PROTECTED CONTROLLER '+m.name+
      ' ('+m.sha256+')\n'+f.content+'\n');
  }
  candidateManifestSha256=hash(doc.candidateManifestJson);
 }
 return Object.freeze({
  head,packDigest,fileCount:doc.files.length,sha256:hash(raw),
  ...(routine?{candidateManifestSha256}:{}),
  readable:'Immutable complete source HEAD '+head+
    '\nOwner-pinned immutable verifier package '+packDigest+
    (routine?'\nController candidate manifest '+candidateManifestSha256:'')+
    '\n'+rendered.join('\n')
 });
}
/** Non-authoritative convenience builder; validation is mandatory even
 * for source assembled by the fixed independently reviewed root stage.
 */
export function makePinnedCodexReviewInput({
  manifestJson,files,candidateManifestJson,candidateFiles
}={}){
 const routine=candidateManifestJson!==undefined||
   candidateFiles!==undefined;
 if(routine&&(typeof candidateManifestJson!=='string'||
     !Array.isArray(candidateFiles)))deny();
 const raw=JSON.stringify({
  version:2,manifestJson,files,
  ...(routine?{candidateManifestJson,candidateFiles}:{})
 });
 let m,c;
 try{
  m=JSON.parse(manifestJson);
  if(routine)c=JSON.parse(candidateManifestJson);
 }catch{deny();}
 validatePinnedCodexSourceReviewInput({
  raw,head:routine?c.commit:m.head,packDigest:hash(manifestJson)
 });
 return raw;
}

/** A non-authoritative claim constructor. Only an audited runner holding
 * a separately protected operating signer key may sign this JSON.
 */
export function makeCodexReceiptClaim({
  terminal,head,base,reviewRunId,nowMs,packDigest,reviewInputSha256,
  candidateManifestSha256
}={}){
  if(terminal?.verdict!=='PASS'||terminal.head!==head||
     terminal.base!==base||!SHA.test(head||'')||!SHA.test(base||'')||
     !RUN.test(reviewRunId||'')||!Number.isSafeInteger(nowMs)||
     nowMs<1||!/^([0-9a-f]{64})$/.test(terminal.terminalSha256||''))deny();
  const v2=packDigest!==undefined||reviewInputSha256!==undefined;
  if(v2&&(!HASH.test(packDigest||'')||
     !HASH.test(reviewInputSha256||'')))deny();
  if(candidateManifestSha256!==undefined&&
     (!v2||!HASH.test(candidateManifestSha256)))deny();
  return JSON.stringify({
    version:v2?2:1,repository:'al-hub/mcp-dev-hub',prNumber:39,
    head,base,reviewer:'independent-codex',reviewRunId,
    reviewVerdict:'PASS',findings:[],
    ...(v2?{packDigest,reviewInputSha256,
      terminalSha256:terminal.terminalSha256,
      ...(candidateManifestSha256!==undefined?{candidateManifestSha256}:{})}:{}),
    issuedAtMs:nowMs,expiresAtMs:nowMs+120000
  });
}
