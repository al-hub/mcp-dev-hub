// #35 Gate B groundwork ONLY: verify a signed, narrowly scoped approval.
// This module neither fetches trustworthy GitHub evidence nor installs files.
// A separate root-owned verifier MUST establish the CI/review provenance,
// retrieve immutable bytes, pin the trust key outside the checkout and keep a
// durable anti-replay journal before permitting any privileged side effect.
import {createHash, createPublicKey, verify} from 'node:crypto';
import {validateProposedProtectedUpdate, PROTECTED_REPOSITORY}
  from './protected-update-manifest.mjs';

export const APPROVAL_DOMAIN = 'mcp-dev-hub/protected-update-approval/v1\n';
const SHA = /^[a-f0-9]{40}$/;
const DIGEST = /^[a-f0-9]{64}$/;
const ID = /^[a-f0-9]{32}$/;
const SIGNATURE_B64 = /^[A-Za-z0-9+/]{86}==$/;
const FIELDS = Object.freeze([
  'version','repository','scope','head','base','manifestSha256',
  'ciRunId','ciHead','reviewHead','reviewBase','reviewDigest','reviewVerdict',
  'operationId','issuedAtMs','expiresAtMs'
]);
const fail = () => { throw Error('invalid_protected_approval'); };
const sha256 = text => createHash('sha256').update(text,'utf8').digest('hex');
const keysExact = value => value!==null && typeof value==='object' &&
  !Array.isArray(value) &&
  Object.keys(value).length===FIELDS.length &&
  FIELDS.every(field=>Object.hasOwn(value,field));

/**
 * Read-only cryptographic guard. Every trusted* argument MUST be acquired
 * independently by the immutable root verifier, never from Issue text or
 * the worker's checkout. The signature does NOT independently prove that
 * GitHub CI or Codex genuinely passed.
 */
export function verifySignedProtectedUpdateApproval({
  manifestJson, approvalJson, signatureBase64, trustPublicKeyPem,
  trustedHead, trustedBase, trustedOperationId, nowMs
} = {}) {
  if(typeof approvalJson!=='string' ||
      Buffer.byteLength(approvalJson,'utf8')>2048 ||
      typeof manifestJson!=='string' ||
      !SHA.test(trustedHead||'') || !SHA.test(trustedBase||'') ||
      trustedHead===trustedBase ||
      !ID.test(trustedOperationId||'') ||
      !Number.isSafeInteger(nowMs) || nowMs<=0) fail();
  let a;
  try { a=JSON.parse(approvalJson); } catch { fail(); }
  // Canonical JSON rules out duplicate keys, ambiguous encodings and
  // unexpected whitespace: the signed bytes and parsed bytes are identical.
  if(!keysExact(a) || JSON.stringify(a)!==approvalJson ||
      a.version!==1 || a.repository!==PROTECTED_REPOSITORY ||
      a.scope!=='controller-pair' ||
      a.head!==trustedHead || a.base!==trustedBase ||
      a.head===a.base || a.ciHead!==a.head ||
      a.reviewHead!==a.head || a.reviewBase!==a.base ||
      a.reviewVerdict!=='PASS' ||
      !DIGEST.test(a.reviewDigest||'') ||
      a.operationId!==trustedOperationId ||
      !Number.isSafeInteger(a.ciRunId) || a.ciRunId<=0 ||
      !Number.isSafeInteger(a.issuedAtMs) ||
      !Number.isSafeInteger(a.expiresAtMs) ||
      a.issuedAtMs>nowMs || a.expiresAtMs<nowMs ||
      a.expiresAtMs<=a.issuedAtMs ||
      a.expiresAtMs-a.issuedAtMs>600000 ||
      a.manifestSha256!==sha256(manifestJson)) fail();

  // Parser checks file allowlist and exact bundle, not CI authorization.
  const manifest=validateProposedProtectedUpdate(manifestJson,{
    verifiedCommit:trustedHead
  });
  if(manifest.commit!==a.head || manifest.bundle!==a.scope) fail();
  if(typeof signatureBase64!=='string' ||
     !SIGNATURE_B64.test(signatureBase64)) fail();
  const signature=Buffer.from(signatureBase64,'base64');
  if(signature.length!==64 || signature.toString('base64')!==signatureBase64)
    fail();
  // The public key must be root-owned/pinned OUTSIDE the repository and
  // cannot be substituted by a caller-supplied manifest field.
  let key;
  try { key=createPublicKey(trustPublicKeyPem); }
  catch { throw Error('invalid_trust_key'); }
  if(key.asymmetricKeyType!=='ed25519') throw Error('invalid_trust_key');
  const message=Buffer.from(APPROVAL_DOMAIN+approvalJson,'utf8');
  if(!verify(null,message,key,signature))
    throw Error('invalid_approval_signature');
  return Object.freeze({
    operationId:a.operationId, head:a.head, base:a.base,
    ciRunId:a.ciRunId, reviewDigest:a.reviewDigest,
    manifestSha256:a.manifestSha256, manifest
  });
}
