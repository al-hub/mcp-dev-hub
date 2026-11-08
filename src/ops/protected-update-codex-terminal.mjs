// #35 source-only verifier for the FINAL persisted result of a real Codex run.
// This pure module is not a signer: synthetic calls cannot authorize a review.
// Only the separately installed, OS-pinned immutable runner can generate a
// signed receipt after it personally launches Codex and validates its result.
import {createHash} from 'node:crypto';

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

/** A non-authoritative claim constructor. Only an audited runner holding
 * a separately protected operating signer key may sign this JSON.
 */
export function makeCodexReceiptClaim({
  terminal,head,base,reviewRunId,nowMs
}={}){
  if(terminal?.verdict!=='PASS'||terminal.head!==head||
     terminal.base!==base||!SHA.test(head||'')||!SHA.test(base||'')||
     !RUN.test(reviewRunId||'')||!Number.isSafeInteger(nowMs)||
     nowMs<1||!/^([0-9a-f]{64})$/.test(terminal.terminalSha256||''))deny();
  return JSON.stringify({
    version:1,repository:'al-hub/mcp-dev-hub',prNumber:39,
    head,base,reviewer:'independent-codex',reviewRunId,
    reviewVerdict:'PASS',findings:[],
    issuedAtMs:nowMs,expiresAtMs:nowMs+120000
  });
}
