// Deliberately conservative candidate detection, not a proof of privacy.
export function inspectFile(path, content) {
  const findings = [];
  if (/(^|\/)(\.env(?:\..*)?|\.ssh|private|state|data|logs|artifacts|\.claude|\.gemini|\.codex)(\/|$)/.test(path)
    || /(?:\.local\.[^/]+|\.(?:pem|key|p12|pfx|log|db|sqlite\d*)(?:-\w+)?|id_rsa|id_ed25519|known_hosts)$/.test(path)
    || (path.startsWith('config/') && path !== 'config/hub.example.json')
    || path === '.mcp.json') findings.push('private-runtime-path');
  const rules = [
    ['private-key', /-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----/],
    ['provider-token', /\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{20,}|AKIA[A-Z0-9]{16})\b/],
    ['email-address', /\b[A-Za-z0-9._%+-]+@(?!(?:example\.(?:com|org|net)|[^\s@]+\.invalid)\b)[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/],
    ['ipv4-address', /\b(?:\d{1,3}\.){3}\d{1,3}\b/],
    ['personal-absolute-path', /(?:\/home\/|\/Users\/|[A-Za-z]:\\Users\\)[A-Za-z0-9_.-]+/],
    ['credential-assignment', /["']?(?:password|api[_-]?key|access[_-]?token|secret)["']?\s*[:=]\s*["'][^<>\s][^"'\n]{7,}["']/i]
  ];
  for (const [category, pattern] of rules) if (pattern.test(content)) findings.push(category);
  return findings;
}
