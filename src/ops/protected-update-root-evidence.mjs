// #35 immutable-root evidence adapter candidate — NOT INSTALLED.
// This module cannot grant privilege. A separate, reviewed one-time admin
// bootstrap must pin it as immutable root-owned code and configure only fixed
// root-held trust anchors. Never call from mutable checkout with root authority.
import {
  constants,closeSync,fstatSync,lstatSync,openSync,readFileSync
} from 'node:fs';
import {createPublicKey} from 'node:crypto';
import {verifySignedProtectedUpdateApproval}
  from './protected-update-approval.mjs';
import {
  fetchAndVerifyGitHubUpdateEvidence,fetchAndVerifyGitHubControllerPair
} from './protected-update-github-evidence.mjs';

const TRUST_DIR='/etc/mcp-dev-hub/protected-update';
const PATHS=['/','/etc','/etc/mcp-dev-hub',TRUST_DIR];
const fail=()=>{throw Error('protected_root_evidence_denied');};
const readFlags=constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK;
const rootOnly=(st)=>st.uid===0&&(st.mode&0o022)===0;
const OWNERS=Object.freeze({
  'github-token':4096,'reviewer-public.pem':4096,
  'codex-reviewer-public.pem':4096,'approval-public.pem':4096,
  'approved-pack-digest':128
});
function checkedRootDirectory(p){
  const st=lstatSync(p);
  if(!st.isDirectory()||st.isSymbolicLink()||!rootOnly(st))fail();
}
function readPinnedFile(name){
  if(!Object.hasOwn(OWNERS,name))fail();
  const path=TRUST_DIR+'/'+name;
  const fd=openSync(path,readFlags);
  try{
    const st=fstatSync(fd);
    if(!st.isFile()||!rootOnly(st)||
       (st.mode&0o077)!==0||
       st.size<1||st.size>OWNERS[name])fail();
    const value=readFileSync(fd,'utf8');
    if(Buffer.byteLength(value,'utf8')!==st.size)fail();
    return value;
  }finally{closeSync(fd);}
}
export function readRootProtectedUpdateTrust(){
  if(typeof process.geteuid!=='function'||process.geteuid()!==0)fail();
  for(const path of PATHS)checkedRootDirectory(path);
  const githubToken=readPinnedFile('github-token');
  const reviewerPublicKeyPem=readPinnedFile('reviewer-public.pem');
  const codexReviewerPublicKeyPem=readPinnedFile('codex-reviewer-public.pem');
  const approvalPublicKeyPem=readPinnedFile('approval-public.pem');
  const approvedPackDigest=readPinnedFile('approved-pack-digest').trim();
  if(!/^[A-Za-z0-9_.-]{8,4096}$/.test(githubToken)||
     !/^[a-f0-9]{64}$/.test(approvedPackDigest))fail();
  try{
    const r=createPublicKey(reviewerPublicKeyPem);
    const c=createPublicKey(codexReviewerPublicKeyPem);
    const a=createPublicKey(approvalPublicKeyPem);
    if(r.asymmetricKeyType!=='ed25519'||
       c.asymmetricKeyType!=='ed25519'||
       a.asymmetricKeyType!=='ed25519')fail();
    const pub=k=>k.export({type:'spki',format:'der'});
    if(pub(r).equals(pub(c))||pub(r).equals(pub(a))||
       pub(c).equals(pub(a)))fail();
  }catch{fail();}
  // Token is NEVER serialized/logged or returned through any public API.
  return Object.freeze({
    githubToken,reviewerPublicKeyPem,codexReviewerPublicKeyPem,
    approvalPublicKeyPem,approvedPackDigest
  });
}
/** Root process only: GitHub verification, separately signed review, signed
 * approval verification, fixed-source SHA check. No root file effects.
 * This does NOT verify an issuer's operational independence by itself.
 * The fixed root bootstrap must pin identities/config and disallow caller-
 * controlled token/key selection.
 */
export async function preflightAuthenticatedProtectedUpdate({
  prNumber,head,base,ciRunId,operationId,nowMs,
  reviewJson,reviewSignatureBase64,
  approvalJson,signatureBase64,manifestJson
}={}){
  // Reject malformed input BEFORE reading any root-held credential.
  if(typeof head!=='string'||!/^[a-f0-9]{40}$/.test(head)||
     typeof base!=='string'||!/^[a-f0-9]{40}$/.test(base)||
     head===base||
     typeof operationId!=='string'||!/^[a-f0-9]{32}$/.test(operationId)||
     !Number.isSafeInteger(prNumber)||prNumber<1||
     !Number.isSafeInteger(ciRunId)||ciRunId<1||
     !Number.isSafeInteger(nowMs)||nowMs<1||
     typeof reviewJson!=='string'||typeof approvalJson!=='string'||
     typeof manifestJson!=='string'||typeof signatureBase64!=='string'||
     typeof reviewSignatureBase64!=='string')fail();
  const trust=readRootProtectedUpdateTrust();
  const proof=await fetchAndVerifyGitHubUpdateEvidence({
    prNumber,head,base,ciRunId,nowMs,reviewJson,
    reviewSignatureBase64,githubToken:trust.githubToken,
    pinnedReviewerPublicKeyPem:trust.codexReviewerPublicKeyPem,
    pinnedApprovalPublicKeyPem:trust.approvalPublicKeyPem
  });
  const approved=verifySignedProtectedUpdateApproval({
    manifestJson,approvalJson,signatureBase64,
    trustPublicKeyPem:trust.approvalPublicKeyPem,
    trustedHead:head,trustedBase:base,
    trustedOperationId:operationId,nowMs
  });
  if(approved.ciRunId!==ciRunId||
     approved.reviewDigest!==proof.reviewDigest||
     approved.head!==proof.head||approved.base!==proof.base)fail();
  const contents=await fetchAndVerifyGitHubControllerPair({
    head,manifestFiles:approved.manifest.files,
    githubToken:trust.githubToken
  });
  return Object.freeze({approved,proof,contents});
}
// This read-only adapter deliberately has NO "install", "sudo", "switch",
// "grant", "retry" or "execute" entrypoint.
