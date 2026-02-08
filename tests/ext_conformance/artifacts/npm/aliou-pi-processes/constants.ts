// Stub constants for conformance testing

export const MESSAGE_TYPE_PROCESS_UPDATE = "process:update";

export const LIVE_STATUSES: ProcessStatus[] = ["running", "starting"];

export type ProcessStatus = "running" | "starting" | "stopped" | "error";

export interface ProcessInfo {
  pid: number;
  name: string;
  status: ProcessStatus;
  command: string;
  cwd: string;
  startedAt: number;
}

export interface StartOptions {
  command: string;
  name?: string;
  cwd?: string;
  env?: Record<string, string>;
}

export interface KillResult {
  success: boolean;
  signal: string;
}

export interface ManagerEvent {
  type: string;
  process: ProcessInfo;
}

export interface ExecuteResult {
  success: boolean;
  output?: string;
  error?: string;
}

export interface ProcessesDetails {
  processes: ProcessInfo[];
  total: number;
  running: number;
}
