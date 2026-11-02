// Durable AI development claims: a review finding can request one bounded fix,
// but cannot approve, merge, or silently replay unknown work.
const SHA=/^[a-f0-9]{40}$/;
const ID=/^[a-z0-9][a-z0-9_-]{2,63}$/;
export function ensureDevelopmentClaims(db){
 db.exec(`CREATE TABLE IF NOT EXISTS ai_development_claims(
  job_id TEXT PRIMARY KEY, head_sha TEXT NOT NULL, phase TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0, updated_at TEXT NOT NULL, last_reason TEXT
 )`);
 if(!db.prepare('PRAGMA table_info(ai_development_claims)').all().some(c=>c.name==='last_reason'))
   db.exec('ALTER TABLE ai_development_claims ADD COLUMN last_reason TEXT');
}
export function claimDevelopment(db,{jobId,headSha,at=new Date().toISOString()}){
 if(!ID.test(jobId)||!SHA.test(headSha))throw Error('invalid development claim');
 ensureDevelopmentClaims(db);
 const row=db.prepare('SELECT head_sha,phase,attempts FROM ai_development_claims WHERE job_id=?').get(jobId);
 if(row)return {claimed:false,...row};
 const result=db.prepare("INSERT OR IGNORE INTO ai_development_claims(job_id,head_sha,phase,attempts,updated_at) VALUES(?,?,'claimed',1,?)").run(jobId,headSha,at);
 return {claimed:result.changes===1,head_sha:headSha,phase:'claimed',attempts:1};
}
export function transitionDevelopment(db,{jobId,headSha,from,to,at=new Date().toISOString()}){
 if(!ID.test(jobId)||!SHA.test(headSha)||!['claimed','running','edited','tested','reviewed','pushing','blocked'].includes(from)||
    !['running','edited','tested','reviewed','pushing','pushed','blocked'].includes(to))throw Error('invalid development transition');
 ensureDevelopmentClaims(db);
 return db.prepare('UPDATE ai_development_claims SET phase=?,updated_at=? WHERE job_id=? AND head_sha=? AND phase=?')
 .run(to,at,jobId,headSha,from).changes===1;
}
export function finishDevelopment(db,{jobId,headSha,from,to,reason,at=new Date().toISOString()}){
 if(!ID.test(jobId)||!SHA.test(headSha)||
    !['claimed','running','edited','tested','reviewed','pushing'].includes(from)||
    !['failed','blocked','unknown'].includes(to)||
    typeof reason!=='string'|| !/^[a-z][a-z0-9_]{2,63}$/.test(reason))
  throw Error('invalid terminal development state');
 ensureDevelopmentClaims(db);
 return db.prepare('UPDATE ai_development_claims SET phase=?,last_reason=?,updated_at=? WHERE job_id=? AND head_sha=? AND phase=?')
  .run(to,reason,at,jobId,headSha,from).changes===1;
}
export function authorizeCommit(db,{jobId,headSha,verifiedBaseSha,testsPassed,codexReviewed,changedPaths}){
 if(!SHA.test(headSha)||verifiedBaseSha!==headSha||testsPassed!==true||codexReviewed!==true||
    !Array.isArray(changedPaths)||changedPaths.length===0||
    changedPaths.some(p=>typeof p!=='string'||!/^tests\/[a-z0-9][a-z0-9_.-]*\.test\.mjs$/.test(p)))return false;
 ensureDevelopmentClaims(db);
 const row=db.prepare('SELECT phase,head_sha FROM ai_development_claims WHERE job_id=?').get(jobId);
 return row?.head_sha===headSha&&row.phase==='reviewed';
}
