// #36: Worker intake boundary: durable attempt before a bounded live Issue GET.
// Opt-in only: independently trusted policy and read-token providers are required.
// Never dispatch development, write to GitHub, or replay unknown/429 outcomes.
import {recordLiveGitHubIssueCandidate} from './issue-intake-github.mjs';

const REPO='al-hub/mcp-dev-hub';
const HASH=/^[0-9a-f]{64}$/;
const deny=()=>{throw Error('issue_intake_poll_unavailable');};

export function ensureIssueIntakePollLedger(db){
 db.exec("CREATE TABLE IF NOT EXISTS issue_intake_poll_attempts ("+
  "repository TEXT NOT NULL, issue_number INTEGER NOT NULL, "+
  "policy_digest TEXT NOT NULL, state TEXT NOT NULL "+
  "CHECK(state IN ('unknown','candidate_only','blocked','conflict')), "+
  "recorded_at TEXT NOT NULL, updated_at TEXT NOT NULL, "+
  "PRIMARY KEY(repository,issue_number))");
}

/**
 * Persist UNKNOWN before network I/O, so restart/reconnect cannot replay.
 * Every new Issue requires its own trusted policy. No automated reset API.
 */
export async function pollAuthorizedIssueOnce({
 db,issueNumber,policy,verifyPolicy,tokenProvider,fetchImpl,
 nowMs=Date.now()
}={}){
 if(!db||typeof db.exec!=='function'||typeof db.prepare!=='function'||
    !Number.isSafeInteger(issueNumber)||issueNumber<1||
    !Number.isSafeInteger(nowMs)||nowMs<0||
    typeof verifyPolicy!=='function'||typeof tokenProvider!=='function'||
    !policy||policy.version!==1||policy.repository!==REPO||
    policy.issueNumber!==issueNumber||!HASH.test(policy.policyDigest||'')||
    !Number.isSafeInteger(policy.expiresAtMs)||
    policy.expiresAtMs<=nowMs||policy.expiresAtMs>nowMs+86400000)deny();
 // Issue body, labels, model output and env flags cannot self-authorize.
 try{if(verifyPolicy(policy)!==true)deny();}catch{deny();}
 ensureIssueIntakePollLedger(db);
 const at=new Date(nowMs).toISOString();
 db.exec('BEGIN IMMEDIATE');
 try{
  const previous=db.prepare("SELECT state,policy_digest AS digest FROM "+
   "issue_intake_poll_attempts WHERE repository=? AND issue_number=?")
   .get(REPO,issueNumber);
  if(previous){
   const same=previous.digest===policy.policyDigest;
   let state=same?previous.state:'conflict';
   // An earlier poll claim is not proof the immutable candidate still exists.
   // A later terminal block or missing ledger row must not appear admitted.
   // Reconcile only local SQLite state; NEVER repeat the external Issue GET.
   if(same&&state==='candidate_only'){
    const candidate=db.prepare("SELECT state FROM issue_intake_candidates "+
     "WHERE repository=? AND issue_id=? AND issue_number=? "+
     "AND issue_updated_at=? AND policy_digest=? AND base_sha=?")
     .get(REPO,policy.issueId,issueNumber,policy.issueUpdatedAt,
      policy.policyDigest,policy.baseSha);
    state=candidate?.state==='candidate_only'?'candidate_only':
     candidate?.state==='blocked'?'blocked':'unknown';
   }
   db.exec('COMMIT');
   return Object.freeze({state,attempted:false});
  }
  db.prepare("INSERT INTO issue_intake_poll_attempts "+
   "(repository,issue_number,policy_digest,state,recorded_at,updated_at) "+
   "VALUES(?,?,?,'unknown',?,?)")
   .run(REPO,issueNumber,policy.policyDigest,at,at);
  db.exec('COMMIT');
 }catch{db.exec('ROLLBACK');deny();}
 try{
  const result=await recordLiveGitHubIssueCandidate({
   db,issueNumber,policy,verifyPolicy,tokenProvider,fetchImpl,nowMs
  });
  const state=result.state==='candidate_only'?'candidate_only':
   ['blocked','unknown','conflict'].includes(result.state)?result.state:'unknown';
  db.prepare("UPDATE issue_intake_poll_attempts SET state=?,updated_at=? "+
    "WHERE repository=? AND issue_number=? AND state='unknown'")
   .run(state,at,REPO,issueNumber);
  return Object.freeze({state,attempted:true});
 }catch{
  // Precommitted UNKNOWN remains terminal and requires external reconciliation.
  return Object.freeze({state:'unknown',attempted:true});
 }
}
