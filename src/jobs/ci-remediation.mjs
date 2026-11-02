// Fail-closed decisions for AI-assisted correction of deterministic CI failures.
// A new reviewed commit, not a rerun of the same SHA, is required for every fix.
export const MAX_FIX_ATTEMPTS=3;
export function decideCiRemediation({attempts=0,reason,headSha,observedSha,reviewerIndependent=false,approvalRequired=false}={}){
 if(!Number.isSafeInteger(attempts)||attempts<0||typeof reason!=='string')throw Error('invalid remediation state');
 if(!/^[a-f0-9]{40}$/.test(headSha??'')||headSha!==observedSha)return {state:'reconcile',allowed:false};
 if(approvalRequired)return {state:'blocked',allowed:false,reason:'approval_required'};
 if(!['test_failure','compile_failure','lint_failure'].includes(reason))return {state:'blocked',allowed:false,reason:'not_code_failure'};
 if(attempts>=MAX_FIX_ATTEMPTS)return {state:'blocked',allowed:false,reason:'fix_budget_exhausted'};
 if(!reviewerIndependent)return {state:'blocked',allowed:false,reason:'independent_review_required'};
 return {state:'fix_required',allowed:true,nextAttempt:attempts+1,requiresNewSha:true};
}
export function acceptFixedHead({oldSha,newSha,ciPassed,independentReviewPassed,acceptancePassed}={}){
 if(!/^[a-f0-9]{40}$/.test(oldSha??'')||!/^[a-f0-9]{40}$/.test(newSha??'')||oldSha===newSha)
   return {state:'blocked',merge:false,reason:'new_commit_required'};
 if(!ciPassed||!independentReviewPassed||!acceptancePassed)return {state:'verification_required',merge:false};
 return {state:'merge_eligible',merge:true};
}
