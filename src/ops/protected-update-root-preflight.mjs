// #35 fixed root-side READ-ONLY preflight candidate, NOT a deployable
// administrator entrypoint. Its only input is canonical nonexecutable data.
// The immutable bootstrap must pin this module and dependency hashes outside
// the checkout and must verify all ancestors before any privileged mutation.
import {parseProtectedUpdateRequest}
  from './protected-update-request.mjs';
import {assertFixedRootProtectedUpdateLayout}
  from './protected-update-root-layout.mjs';
import {preflightAuthenticatedProtectedUpdate}
  from './protected-update-root-evidence.mjs';
import {
  inspectProtectedCurrentSnapshot,inspectProtectedReleaseStaging
} from './protected-update-release-pointer.mjs';

const ROOT='/usr/local/lib/mcp-dev-hub';
const deny=()=>{throw Error('protected_root_preflight_denied');};

/** Never takes target paths, systemctl commands, uid, credentials, signing
 * keys or the filesystem's claimed previous hashes from a Worker request.
 * It does not create journal entries, install, switch, sign or restart.
 */
export async function preflightRootProtectedUpdateRequest(raw){
  const request=parseProtectedUpdateRequest(raw);
  // Before reading root-held credentials or trusting any installed release,
  // validate every fixed ancestor of both protected roots via real lstat.
  assertFixedRootProtectedUpdateLayout();
  const nowMs=Date.now(); // immutable supervisor clock, not request-controlled
  const verified=await preflightAuthenticatedProtectedUpdate({
    ...request,nowMs
  });
  if(verified.approved.head!==request.head||
     verified.approved.base!==request.base||
     verified.approved.operationId!==request.operationId)deny();
  const current=inspectProtectedCurrentSnapshot(ROOT);
  if(current.commit===request.head)deny();
  const staging=inspectProtectedReleaseStaging(ROOT,{
    commit:request.head,files:verified.approved.manifest.files,
    contents:verified.contents
  });
  // No privileged side effect, no token, no private key, no source buffer.
  // This report is INFORMATION ONLY, never an authorization token.
  return Object.freeze({
    state:'preflight_only',operationId:request.operationId,
    head:request.head,base:request.base,previousCommit:current.commit,
    targetAlreadyStaged:staging.existing,ciRunId:request.ciRunId
  });
}
