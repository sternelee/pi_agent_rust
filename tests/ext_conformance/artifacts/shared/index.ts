// Stub shared module for qualisero monorepo extensions
// (qualisero-background-notify and qualisero-safe-git both import from ../../shared)

export interface BackgroundNotifyConfig {
  enabled: boolean;
  sound: boolean;
  speech: boolean;
  notification: boolean;
}

export interface TerminalInfo {
  name: string;
  pid: number;
  isBackground: boolean;
}

export const BEEP_SOUNDS = ["default", "subtle", "alert"];
export const SAY_MESSAGES = ["Task complete", "Done"];

export function getBackgroundNotifyConfig(): BackgroundNotifyConfig {
  return { enabled: false, sound: false, speech: false, notification: false };
}

export function playBeep(_sound?: string): void {}
export function displayOSXNotification(_title: string, _body: string): void {}
export function speakMessage(_message: string): void {}
export function bringTerminalToFront(): void {}

export function detectTerminalInfo(): TerminalInfo {
  return { name: "unknown", pid: 0, isBackground: false };
}

export function isTerminalInBackground(): boolean {
  return false;
}

export function checkSayAvailable(): boolean {
  return false;
}

export function loadPronunciations(): Record<string, string> {
  return {};
}

export function checkTerminalNotifierAvailable(): boolean {
  return false;
}

export function isTerminalNotifierAvailable(): boolean {
  return false;
}

export function getCurrentDirName(): string {
  return "";
}

export function replaceMessageTemplates(
  template: string,
  _vars?: Record<string, string>,
): string {
  return template;
}

export function notifyOnConfirm(
  _config: BackgroundNotifyConfig,
  _terminal: TerminalInfo,
): void {}
