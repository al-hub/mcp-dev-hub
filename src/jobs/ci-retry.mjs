// CI recovery classifier. Retries are scoped to a single workflow run and head SHA.
// This module does not invoke GitHub or bypass required checks.
export const MAX_CI_RETRIES = 3;
export const CI_RETRY_DELAYS_MS = Object.freeze([10_000, 30_000, 90_000]);
const TRANSIENT = new Set(['runner_lost', 'network', 'rate_limit', 'github_service']);
export function decideCiRetry({retryCount=0, reason, sameHead=true, runCompleted=true, anotherControllerActive=false} = {}) {
  if (!Number.isSafeInteger(retryCount) || retryCount < 0) throw new Error('invalid retry count');
  if (typeof reason !== 'string') throw new Error('invalid reason');
  if (!sameHead || !runCompleted || anotherControllerActive) return {state:'reconcile',retry:false,delayMs:null};
  if (!TRANSIENT.has(reason) || retryCount >= MAX_CI_RETRIES) return {state:'blocked',retry:false,delayMs:null};
  return {state:'retry_scheduled',retry:true,delayMs:CI_RETRY_DELAYS_MS[retryCount],nextRetryCount:retryCount+1};
}
