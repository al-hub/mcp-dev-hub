// #35 UNINSTALLED trusted App publisher. Never invoke checkout source as root.
// An owner-approved immutable package and separately authenticated acceptance
// packet are prerequisites; this command does not invent gate evidence.
import {fileURLToPath} from 'node:url';
import {createHash,createPublicKey} from 'node:crypto';
import {readRootProtectedUpdateTrust}
 from '../src/ops/protected-update-root-evidence.mjs';
import {trustedDirectory,trustedFile,parseTrustedAppConfiguration,
 getInstallation} from './reviewer-app-trusted-preflight.mjs';
import {verifyProtectedBootstrapPack} from './protected-update-bootstrap-pack.mjs';
import {readFixedIndependentCodexReceipt}
 from '../src/ops/protected-update-issuer-runtime.mjs';
import {fetchAndVerifyGitHubBootstrapEvidence}
 from '../src/ops/protected-update-github-evidence.mjs';
import {createScopedAppClient,publishIndependentApproval,
 validateReviewEvidence,validateProtectionEvidence}
 from '../src/jobs/github-app-review-publisher.mjs';
import {fenceApprovalPost} from '../src/jobs/github-app-publication-fence.mjs';
import {verifySignedAppAcceptance}
 from '../src/ops/protected-update-app-acceptance.mjs';

const PACK='/usr/local/lib/mcp-dev-hub/protected-updater';
const ENTRY=PACK+'/code/scripts/reviewer-app-trusted-publish.mjs';
const TRUST='/etc/mcp-dev-hub/protected-update';
// Approval POST intents are independent of the root update journal.
// The issuer provisioner creates this root-only 0700 folder before App POST.
const STATE='/var/lib/mcp-dev-hub-signers/app-publication';
const deny=()=>{throw Error('trusted_app_publication_denied_or_unknown');};
const digest=s=>createHash('sha256').update(s).digest('hex');
export async function publishFixedTrustedAppApproval(){
 if(process.getuid?.()!==0||process.geteuid?.()!==0||
    process.argv.length!==2||fileURLToPath(import.meta.url)!==ENTRY)deny();
 for(const p of ['/','/usr','/usr/local','/usr/local/lib',
  '/usr/local/lib/mcp-dev-hub',PACK,'/etc','/etc/mcp-dev-hub',TRUST,
  '/var','/var/lib','/var/lib/mcp-dev-hub-signers'])trustedDirectory(p);
 trustedDirectory(STATE,true);
 const packDigest=trustedFile(TRUST+'/approved-pack-digest',0o400,128).trim();
 if(!/^[a-f0-9]{64}$/.test(packDigest))deny();
 const pack=verifyProtectedBootstrapPack({
  outputPath:PACK,expectedManifestSha256:packDigest
 });
 const config=parseTrustedAppConfiguration(
  trustedFile('/etc/mcp-dev-hub/reviewer-app-preflight.json',0o400,2048));
 if(config.expectedHead!==pack.head)deny();
 // A root-owned JSON file plus a root-owned digest is NOT independent
 // authorization. The existing separately pinned approval principal must
 // sign the complete, short-lived acceptance packet in a distinct domain.
 // This publisher neither creates signatures nor changes trust anchors.
 const raw=trustedFile(TRUST+'/app-acceptance.json',0o400,12000);
 const pin=trustedFile(TRUST+'/app-acceptance.sha256',0o400,128).trim();
 const signature=trustedFile(TRUST+'/app-acceptance.sig',0o400,256).trim();
 const reviewSignature=trustedFile(
  TRUST+'/app-acceptance.review.sig',0o400,256).trim();
 if(!/^[a-f0-9]{64}$/.test(pin)||digest(raw)!==pin)deny();
 let claim;
 try{claim=JSON.parse(raw);}catch{deny();}
 const receipt=readFixedIndependentCodexReceipt();
 const trust=readRootProtectedUpdateTrust();
 const accepted=()=>verifySignedAppAcceptance({
  raw,signatureBase64:signature,
  reviewSignatureBase64:reviewSignature,
  pinnedReviewerPublicKeyPem:trust.reviewerPublicKeyPem,
  pinnedApprovalPublicKeyPem:trust.approvalPublicKeyPem,
  head:pack.head,base:claim?.base,ciRunId:claim?.ciRunId,
  packDigest,nowMs:Date.now()
 });
 const packet=accepted().packet;
 const pub=p=>createPublicKey(p).export({type:'spki',format:'der'});
 if(trust.approvedPackDigest!==packDigest||
    !pub(receipt.codexReviewerPublicKeyPem).equals(pub(trust.codexReviewerPublicKeyPem))||
    !pub(receipt.issuerReviewerPublicKeyPem).equals(pub(trust.reviewerPublicKeyPem)))deny();
 const args={
  prNumber:39,headSha:packet.head,baseSha:packet.base,packDigest,
  evidence:packet.evidence,verifyEvidence:e=>e===packet.evidence,
  protectionEvidence:packet.protectionEvidence,
  verifyProtectionEvidence:p=>p===packet.protectionEvidence,
  signedCodexReceipt:{reviewJson:receipt.reviewJson,
   signatureBase64:receipt.reviewSignatureBase64},
  pinnedCodexPublicKeyPem:receipt.codexReviewerPublicKeyPem,
  pinnedIssuerReviewerPublicKeyPem:receipt.issuerReviewerPublicKeyPem
 };
 validateReviewEvidence(args);
 validateProtectionEvidence(args);
 // Independently refetch CI/protection using the existing separately scoped
 // read token, BEFORE accessing the App key or exchanging a write token.
 const token=trust.githubToken;
 await fetchAndVerifyGitHubBootstrapEvidence({
  prNumber:39,head:packet.head,base:packet.base,
  ciRunId:packet.ciRunId,githubToken:token
 });
 const keyParent=config.keyFile.slice(0,config.keyFile.lastIndexOf('/'));
 trustedDirectory('/etc/mcp-dev-hub',true);
 if(keyParent!=='/etc/mcp-dev-hub')trustedDirectory(keyParent,true);
 const key=trustedFile(config.keyFile,0o600,16384);
 const installationId=await getInstallation({appId:config.appId,key});
 const client=await createScopedAppClient({
  appId:config.appId,installationId,repositoryId:1440361577,key,prNumber:39
 });
 if(client.actor!=='mcp-dev-hub-ai-reviewer[bot]')deny();
 const api=fenceApprovalPost({
  api:client.api,directory:STATE,owner:0,
  // Check again immediately before writing the irreversible POST intent;
  // an expired signature must not create a false UNKNOWN POST outcome.
  validateBeforePost:accepted,
  head:packet.head,base:packet.base,evidenceId:packet.evidence.evidenceId
 });
 const result=await publishIndependentApproval({...args,api,actor:client.actor});
 accepted();
 return Object.freeze({state:result.state,headSha:result.headSha,
  reviewId:result.reviewId,actor:result.actor,safeToReplay:false});
}
if(process.argv[1]&&fileURLToPath(import.meta.url)===process.argv[1]){
 try{
  process.stdout.write(JSON.stringify(await publishFixedTrustedAppApproval())+'\n');
 }catch{
  process.stderr.write('trusted_app_publication_denied_or_unknown\n');
  process.exitCode=78;
 }
}
