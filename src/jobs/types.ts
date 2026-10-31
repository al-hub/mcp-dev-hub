export type JobState = 'queued' | 'running' | 'succeeded' | 'failed' | 'cancelled' | 'interrupted' | 'unknown';
export interface Job {
  id: string;
  targetId: string;
  workspaceId: string;
  idempotencyKey: string;
  state: JobState;
  createdAt: string;
  updatedAt: string;
}
/** Implement using private SQLite storage in milestone 3. */
export interface JobStore {
  get(id: string): Promise<Job | undefined>;
  createIfAbsent(job: Job): Promise<Job>;
  transition(id: string, expected: JobState, next: JobState): Promise<boolean>;
}
