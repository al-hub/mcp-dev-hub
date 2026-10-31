export interface Workspace { id: string; root: string }
export interface Target {
  id: string;
  kind: 'local' | 'ssh';
  enabled: boolean;
  sshAlias?: string;
  workspaces: Workspace[];
}
export interface HubConfig { version: 1; targets: Target[] }

const identifier = /^[a-z][a-z0-9-]{0,63}$/;
const object = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v);
const absolute = (v: string) => v.startsWith('/') || /^[A-Za-z]:[\\/]/.test(v);

/** Does not echo supplied values, which may contain private data. */
export function validateConfig(input: unknown): HubConfig {
  if (!object(input) || input.version !== 1 || !Array.isArray(input.targets)) {
    throw new Error('Invalid configuration');
  }
  const ids = new Set<string>();
  for (const target of input.targets) {
    if (!object(target) || typeof target.id !== 'string' || !identifier.test(target.id)
      || ids.has(target.id) || !['local', 'ssh'].includes(String(target.kind))
      || typeof target.enabled !== 'boolean' || !Array.isArray(target.workspaces)) {
      throw new Error('Invalid target');
    }
    ids.add(target.id);
    if (target.kind === 'ssh' && (typeof target.sshAlias !== 'string'
      || (target.enabled && !identifier.test(target.sshAlias)))) {
      throw new Error('Invalid SSH alias');
    }
    const workspaceIds = new Set<string>();
    for (const workspace of target.workspaces) {
      if (!object(workspace) || typeof workspace.id !== 'string'
        || !identifier.test(workspace.id) || workspaceIds.has(workspace.id)
        || typeof workspace.root !== 'string' || workspace.root.length === 0
        || (target.enabled && (!absolute(workspace.root) || /[<>\0]/.test(workspace.root)))) {
        throw new Error('Invalid workspace');
      }
      workspaceIds.add(workspace.id);
    }
    if (target.enabled && workspaceIds.size === 0) throw new Error('Workspace required');
  }
  return input as unknown as HubConfig;
}

export function resolveWorkspace(config: HubConfig, targetId: string, workspaceId: string): Workspace {
  const validated = validateConfig(config);
  const target = validated.targets.find(item => item.id === targetId && item.enabled);
  const workspace = target?.workspaces.find(item => item.id === workspaceId);
  if (!workspace) throw new Error('Target or workspace unavailable');
  return workspace;
}
