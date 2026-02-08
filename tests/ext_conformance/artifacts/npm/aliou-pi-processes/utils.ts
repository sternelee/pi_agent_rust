// Stub utils for conformance testing
export function isProcessGroupAlive(_pid: number): boolean {
  return false;
}

export function killProcessGroup(_pid: number, _signal?: string): boolean {
  return false;
}

export function formatRuntime(startTime?: number, endTime?: number): string {
  if (!startTime) return "";
  const end = endTime || Date.now();
  const ms = end - startTime;
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}

export function hasAnsi(str: string): boolean {
  return /\x1b\[/.test(str);
}

export function stripAnsi(str: string): string {
  return str.replace(/\x1b\[[0-9;]*m/g, "");
}

export function truncateCmd(cmd: string, maxLen = 60): string {
  if (cmd.length <= maxLen) return cmd;
  return cmd.slice(0, maxLen - 3) + "...";
}

export function formatStatus(p: { status?: string }): string {
  return p.status || "unknown";
}
