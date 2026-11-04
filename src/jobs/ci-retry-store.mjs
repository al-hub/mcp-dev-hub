import { decideCiRetry } from './ci-retry.mjs';

// The controller is intentionally separate from the reviewer retry budget.
// Consumers must inspect failed job logs before supplying a transient reason.
export function ensureCiRetryTable(db) {
  db.exec(`CREATE TABLE IF NOT EXISTS ci_retry_runs (
    run_id INTEGER PRIMARY KEY, head_sha TEXT NOT NULL, retry_count INTEGER NOT NULL DEFAULT 0
      CHECK(retry_count BETWEEN 0 AND 3), state TEXT NOT NULL, retry_at TEXT,
    reason TEXT, updated_at TEXT NOT NULL
  )`);
}
export function scheduleCiRetry(db, {runId, headSha, reason, runCompleted=true, sameHead=true, now=Date.now()}) {
  if (!Number.isSafeInteger(runId) || runId <= 0 || !/^[0-9a-f]{40}$/.test(headSha) ||
      !Number.isFinite(now)) throw Error('invalid CI identity');
  ensureCiRetryTable(db);
  db.exec('BEGIN IMMEDIATE');
  try {
    const old=db.prepare('SELECT * FROM ci_retry_runs WHERE run_id=?').get(runId);
    if(old && old.head_sha!==headSha) throw Error('CI run head mismatch');
    if(old && old.state!=='observing') {
      db.exec('COMMIT');
      return {state:old.state,retry:false,retryCount:old.retry_count};
    }
    const retryCount=old?.retry_count ?? 0;
    const decision=decideCiRetry({retryCount,reason,runCompleted,sameHead});
    const retryAt=decision.retry ? new Date(now+decision.delayMs).toISOString() : null;
    db.prepare(`INSERT INTO ci_retry_runs(run_id,head_sha,retry_count,state,retry_at,reason,updated_at)
      VALUES(?,?,?,?,?,?,?) ON CONFLICT(run_id) DO UPDATE SET
      retry_count=excluded.retry_count,state=excluded.state,retry_at=excluded.retry_at,
      reason=excluded.reason,updated_at=excluded.updated_at`)
      .run(runId,headSha,decision.nextRetryCount??retryCount,decision.state,retryAt,reason,new Date(now).toISOString());
    db.exec('COMMIT');
    return {...decision,retryAt};
  } catch(e) { db.exec('ROLLBACK'); throw e; }
}
// Claims are atomic. Only one worker may call the GitHub failed-job rerun API.
// An unknown API outcome must be reconciled, never blindly rerun.
export function claimDueCiRetry(db,{runId,now=Date.now()}){
  ensureCiRetryTable(db);
  const result=db.prepare(`UPDATE ci_retry_runs SET state='dispatching',retry_at=NULL,updated_at=?
    WHERE run_id=? AND state='retry_scheduled' AND retry_at<=?`)
    .run(new Date(now).toISOString(),runId,new Date(now).toISOString());
  return result.changes===1;
}
export function markCiRetryOutcome(db,{runId,acknowledged}){
  ensureCiRetryTable(db);
  const state=acknowledged?'reconciling':'unknown';
  const change=db.prepare(`UPDATE ci_retry_runs SET state=?,updated_at=?
    WHERE run_id=? AND state='dispatching'`).run(state,new Date().toISOString(),runId);
  return change.changes===1;
}
export function resumeCiObservation(db,{runId,headSha,confirmedCompleted}){
  ensureCiRetryTable(db);
  if(!confirmedCompleted)return false;
  return db.prepare(`UPDATE ci_retry_runs SET state='observing',updated_at=?
   WHERE run_id=? AND head_sha=? AND state='reconciling'`).run(new Date().toISOString(),runId,headSha).changes===1;
}
