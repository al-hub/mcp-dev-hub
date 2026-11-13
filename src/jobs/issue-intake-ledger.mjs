// #36: durable, non-executable Issue intake. No AI job dispatch or retry.
// Production Worker must separately authenticate policy and GitHub snapshot.
import {safeIssuePath} from './issue-intake-candidate.mjs';

const HASH=/^[a-f0-9]{64}$/;
const SHA=/^[a-f0-9]{40}$/;
const SCOPE=/^[a-z][a-z0-9_-]{2,47}$/;
const REPO='al-hub/mcp-dev-hub';
const deny=()=>{throw Error('invalid_issue_intake_candidate');};

export function ensureIssueIntakeLedger(db){
 db.exec(`CREATE TABLE IF NOT EXISTS issue_intake_candidates(
  candidate_id TEXT PRIMARY KEY,
  repository TEXT NOT NULL,
  issue_id INTEGER NOT NULL,
  issue_number INTEGER NOT NULL,
  issue_updated_at TEXT NOT NULL,
  base_sha TEXT NOT NULL,
  policy_digest TEXT NOT NULL,
  scope_id TEXT NOT NULL,
  allowed_files_json TEXT NOT NULL,
  state TEXT NOT NULL CHECK(state IN ('candidate_only','blocked','unknown')),
  terminal_reason TEXT,
  recorded_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(repository,issue_id)
 )`);
}

function assertCandidate(c){
 if(!c||c.kind!=='issue-intake-candidate-v1'||c.status!=='candidate_only'||
    c.executionAuthorized!==false||c.githubWriteAuthorized!==false||
    c.rootAuthorized!==false||c.repository!==REPO||
    !Number.isSafeInteger(c.issueId)||c.issueId<1||
    !Number.isSafeInteger(c.issueNumber)||c.issueNumber<1||
    !HASH.test(c.candidateId||'')||!HASH.test(c.policyDigest||'')||
    !SHA.test(c.baseSha||'')||!SCOPE.test(c.scopeId||'')||
    typeof c.issueUpdatedAt!=='string'||!Number.isFinite(Date.parse(c.issueUpdatedAt))||
    !Array.isArray(c.allowedFiles)||c.allowedFiles.length<1||
    c.allowedFiles.length>20||c.allowedFiles.some(p=>!safeIssuePath(p))||
    new Set(c.allowedFiles).size!==c.allowedFiles.length)deny();
}

export function recordIssueIntakeCandidate(db,c,{at=new Date().toISOString()}={}){
 assertCandidate(c);
 if(typeof at!=='string'||!Number.isFinite(Date.parse(at)))deny();
 ensureIssueIntakeLedger(db);
 db.exec('BEGIN IMMEDIATE');
 try{
  const row=db.prepare('SELECT * FROM issue_intake_candidates WHERE repository=? AND issue_id=?')
   .get(REPO,c.issueId);
  if(row){
   // An updated Issue/scope with a different digest may NOT silently replace
   // an earlier candidate or resume a terminal/unknown external operation.
   const same=row.candidate_id===c.candidateId&&row.issue_number===c.issueNumber&&
    row.issue_updated_at===c.issueUpdatedAt&&row.base_sha===c.baseSha&&
    row.policy_digest===c.policyDigest&&row.scope_id===c.scopeId&&
    row.allowed_files_json===JSON.stringify(c.allowedFiles);
   db.exec('COMMIT');
   return Object.freeze({state:same?row.state:'conflict',
    inserted:false,candidateId:row.candidate_id});
  }
  db.prepare(`INSERT INTO issue_intake_candidates(
   candidate_id,repository,issue_id,issue_number,issue_updated_at,
   base_sha,policy_digest,scope_id,allowed_files_json,
   state,terminal_reason,recorded_at,updated_at
  ) VALUES(?,?,?,?,?,?,?,?,?,'candidate_only',NULL,?,?)`)
  .run(c.candidateId,REPO,c.issueId,c.issueNumber,c.issueUpdatedAt,
   c.baseSha,c.policyDigest,c.scopeId,JSON.stringify(c.allowedFiles),at,at);
  db.exec('COMMIT');
  return Object.freeze({state:'candidate_only',inserted:true,candidateId:c.candidateId});
 }catch(error){db.exec('ROLLBACK');throw error;}
}

export function readIssueIntake(db,candidateId){
 if(!HASH.test(candidateId||''))deny();
 ensureIssueIntakeLedger(db);
 const row=db.prepare(`SELECT candidate_id AS candidateId,
  repository,issue_id AS issueId,issue_number AS issueNumber,
  base_sha AS baseSha,policy_digest AS policyDigest,state,terminal_reason AS reason
  FROM issue_intake_candidates WHERE candidate_id=?`).get(candidateId);
 return row??null;
}

export function blockIssueIntake(db,candidateId,reason,{at=new Date().toISOString()}={}){
 if(!HASH.test(candidateId||'')||
    !['policy_revoked','stale_issue','scope_conflict','integrity_failed','unknown_outcome'].includes(reason)||
    typeof at!=='string'||!Number.isFinite(Date.parse(at)))deny();
 ensureIssueIntakeLedger(db);
 return db.prepare(`UPDATE issue_intake_candidates
  SET state=?,terminal_reason=?,updated_at=?
  WHERE candidate_id=? AND state='candidate_only'`)
  .run(reason==='unknown_outcome'?'unknown':'blocked',reason,at,candidateId).changes===1;
}
