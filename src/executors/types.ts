/** Contract only. No command executor is implemented in the bootstrap. */
export interface ExecutionRequest {
  targetId: string;
  workspaceId: string;
  executable: string;
  args: string[];
  idempotencyKey: string;
  timeoutMs: number;
}
export interface ExecutionResult {
  jobId: string;
  targetId: string;
  workspaceId: string;
  exitCode: number | null;
  state: 'succeeded' | 'failed' | 'cancelled' | 'interrupted' | 'unknown';
}
export interface Executor {
  start(request: ExecutionRequest): Promise<{ jobId: string }>;
  cancel(jobId: string): Promise<void>;
}
