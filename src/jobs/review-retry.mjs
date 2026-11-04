// Pure retry policy for PR review attempts. No command execution or implicit approval.
export const MAX_RETRIES = 3;
export const RETRY_DELAYS_MS = Object.freeze([10_000, 30_000, 90_000]);
const RETRYABLE = new Set(['timeout', 'rate_limit', 'transient_network', 'service_unavailable']);
export function decideReviewRetry({attempt=1, reason, processAlive=false, outcomeKnown=true} = {}) {
  if (!Number.isSafeInteger(attempt) || attempt < 1) throw new Error('invalid attempt');
  if (typeof reason !== 'string') throw new Error('invalid reason');
  if (processAlive || !outcomeKnown) return {state:'recovering',retry:false,delayMs:null};
  if (!RETRYABLE.has(reason)) return {state:'blocked',retry:false,delayMs:null};
  if (attempt > MAX_RETRIES) return {state:'blocked',retry:false,delayMs:null};
  return {state:'retry_scheduled',retry:true,delayMs:RETRY_DELAYS_MS[attempt-1],nextAttempt:attempt+1};
}
