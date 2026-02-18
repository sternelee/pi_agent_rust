#!/usr/bin/env bash
#
# pi_agent_rust uninstaller
#
# One-liner uninstall:
#   curl -fsSL "https://raw.githubusercontent.com/Dicklesworthstone/pi_agent_rust/main/uninstall.sh" | bash

set -euo pipefail

YES=0
QUIET=0
NO_GUM=0
KEEP_PATH=0
NO_RESTORE_LEGACY=0
PURGE_STATE=0

PATH_MARKER="# pi-agent-rust installer PATH"

STATE_DIR="${XDG_STATE_HOME:-$HOME/.local/state}/pi-agent-rust"
STATE_FILE="$STATE_DIR/install-state.env"
STATE_LOADED=0

PIAR_INSTALL_BIN=""
PIAR_INSTALL_BIN_NAME=""
PIAR_ADOPTED_TYPESCRIPT="0"
PIAR_LEGACY_ALIAS_PATH=""
PIAR_LEGACY_MOVED_FROM=""
PIAR_LEGACY_MOVED_TO=""
PIAR_PATH_MARKER=""
PIAR_AGENT_SKILL_STATUS=""
PIAR_AGENT_SKILL_CLAUDE_PATH=""
PIAR_AGENT_SKILL_CODEX_PATH=""
PIAR_CLAUDE_HOOK_SETTINGS=""
PIAR_GEMINI_HOOK_SETTINGS=""
RESTORE_CONFLICT=0

AGENT_SKILL_NAME="pi-agent-rust"
AGENT_SKILL_MARKER="pi_agent_rust installer managed skill"

HAS_GUM=0
if command -v gum >/dev/null 2>&1 && [ -t 1 ]; then
  HAS_GUM=1
fi

log() {
  [ "$QUIET" -eq 1 ] && return 0
  echo -e "$*"
}

ok() {
  [ "$QUIET" -eq 1 ] && return 0
  if [ "$HAS_GUM" -eq 1 ] && [ "$NO_GUM" -eq 0 ]; then
    gum style --foreground 42 "✓ $*"
  else
    echo -e "\033[0;32m✓\033[0m $*"
  fi
}

warn() {
  [ "$QUIET" -eq 1 ] && return 0
  if [ "$HAS_GUM" -eq 1 ] && [ "$NO_GUM" -eq 0 ]; then
    gum style --foreground 214 "⚠ $*"
  else
    echo -e "\033[1;33m⚠\033[0m $*"
  fi
}

err() {
  if [ "$HAS_GUM" -eq 1 ] && [ "$NO_GUM" -eq 0 ]; then
    gum style --foreground 196 "✗ $*"
  else
    echo -e "\033[0;31m✗\033[0m $*" >&2
  fi
}

usage() {
  cat <<'USAGE'
Usage: uninstall.sh [options]

Options:
  --yes, -y            Skip confirmation prompt
  --keep-path          Keep PATH lines added by installer
  --no-restore-legacy  Do not restore moved TypeScript pi binary
  --purge-state        Remove installer state directory when possible
  --quiet, -q          Suppress non-error output
  --no-gum             Disable gum formatting
  -h, --help           Show this help
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --yes|-y)
      YES=1
      shift
      ;;
    --keep-path)
      KEEP_PATH=1
      shift
      ;;
    --no-restore-legacy)
      NO_RESTORE_LEGACY=1
      shift
      ;;
    --purge-state)
      PURGE_STATE=1
      shift
      ;;
    --quiet|-q)
      QUIET=1
      shift
      ;;
    --no-gum)
      NO_GUM=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      err "Unknown option: $1"
      usage
      exit 1
      ;;
  esac
done

show_header() {
  [ "$QUIET" -eq 1 ] && return 0
  if [ "$HAS_GUM" -eq 1 ] && [ "$NO_GUM" -eq 0 ]; then
    gum style \
      --border normal \
      --border-foreground 196 \
      --padding "0 1" \
      --margin "1 0" \
      "$(gum style --foreground 196 --bold 'pi uninstaller')" \
      "$(gum style --foreground 245 'Removes installer-managed pi_agent_rust artifacts')"
  else
    echo ""
    echo -e "\033[1;31mpi uninstaller\033[0m"
    echo -e "\033[0;90mRemoves installer-managed pi_agent_rust artifacts\033[0m"
    echo ""
  fi
}

prompt_confirm() {
  local prompt="$1"
  local default_yes="${2:-0}"
  if [ "$YES" -eq 1 ]; then
    return 0
  fi

  if [ ! -t 0 ]; then
    if [ "$default_yes" -eq 1 ]; then
      return 0
    fi
    return 1
  fi

  if [ "$HAS_GUM" -eq 1 ] && [ "$NO_GUM" -eq 0 ]; then
    if [ "$default_yes" -eq 1 ]; then
      gum confirm --default "$prompt"
    else
      gum confirm "$prompt"
    fi
    return $?
  fi

  local suffix="[y/N]"
  if [ "$default_yes" -eq 1 ]; then
    suffix="[Y/n]"
  fi

  printf "%s %s " "$prompt" "$suffix"
  local ans
  read -r ans || true
  if [ -z "$ans" ]; then
    if [ "$default_yes" -eq 1 ]; then
      return 0
    fi
    return 1
  fi
  case "$ans" in
    y|Y|yes|YES|Yes)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

load_state() {
  if [ ! -f "$STATE_FILE" ]; then
    return 0
  fi

  # shellcheck disable=SC1090
  source "$STATE_FILE"
  STATE_LOADED=1

  if [ -n "${PIAR_PATH_MARKER:-}" ]; then
    PATH_MARKER="$PIAR_PATH_MARKER"
  fi
}

version_timeout_cmd() {
  if command -v timeout >/dev/null 2>&1; then
    printf '%s\n' "timeout"
    return 0
  fi
  if command -v gtimeout >/dev/null 2>&1; then
    printf '%s\n' "gtimeout"
    return 0
  fi
  printf '%s\n' ""
}

capture_version_line() {
  local path="$1"
  local timeout_cmd=""
  timeout_cmd="$(version_timeout_cmd)"

  local out=""
  if [ -n "$timeout_cmd" ]; then
    out=$("$timeout_cmd" 2 "$path" --version 2>/dev/null | head -1 || true)
  else
    out=$("$path" --version 2>/dev/null | head -1 || true)
  fi
  printf '%s\n' "$out"
}

is_rust_pi_output() {
  local out="$1"
  [[ "$out" =~ ^pi[[:space:]][0-9]+\.[0-9]+\.[0-9]+[[:space:]]\( ]]
}

is_rust_pi_binary() {
  local path="$1"
  [ -x "$path" ] || return 1

  local out
  out="$(capture_version_line "$path")"
  is_rust_pi_output "$out"
}

is_managed_alias() {
  local path="$1"
  [ -f "$path" ] || return 1
  grep -q "pi_agent_rust installer managed alias" "$path" 2>/dev/null
}

is_managed_skill_file() {
  local path="$1"
  [ -f "$path" ] || return 1
  grep -q "$AGENT_SKILL_MARKER" "$path" 2>/dev/null
}

is_expected_skill_directory() {
  local dir="$1"
  [ -n "$dir" ] || return 1
  case "$dir" in
    */skills/${AGENT_SKILL_NAME}) return 0 ;;
    *) return 1 ;;
  esac
}

is_expected_hook_settings_path() {
  local path="$1"
  local agent="$2"
  [ -n "$path" ] || return 1

  case "$agent" in
    claude)
      case "$path" in
        "$HOME/.claude/settings.json"|"$HOME/.config/claude/settings.json"|"$HOME/Library/Application Support/Claude/settings.json")
          return 0
          ;;
      esac
      ;;
    gemini)
      case "$path" in
        "$HOME/.gemini/settings.json"|"$HOME/.gemini-cli/settings.json")
          return 0
          ;;
      esac
      ;;
  esac

  return 1
}

hook_binary_path() {
  if [ -n "${PIAR_INSTALL_BIN:-}" ]; then
    printf '%s\n' "$PIAR_INSTALL_BIN"
    return 0
  fi
  printf '%s\n' ""
}

hook_binary_name() {
  if [ -n "${PIAR_INSTALL_BIN_NAME:-}" ]; then
    printf '%s\n' "$PIAR_INSTALL_BIN_NAME"
    return 0
  fi
  if [ -n "${PIAR_INSTALL_BIN:-}" ]; then
    printf '%s\n' "$(basename "$PIAR_INSTALL_BIN")"
    return 0
  fi
  printf '%s\n' "pi"
}

remove_hook_from_settings() {
  local settings_file="$1"
  local hook_key="$2"
  local matcher="$3"

  if [ -z "$settings_file" ] || [ ! -f "$settings_file" ]; then
    return 0
  fi
  if ! command -v python3 >/dev/null 2>&1; then
    warn "python3 not found; skipping hook cleanup for $settings_file"
    return 0
  fi

  local bin_path
  local bin_name
  bin_path="$(hook_binary_path)"
  bin_name="$(hook_binary_name)"

  local py_result=""
  if ! py_result=$(python3 - "$settings_file" "$hook_key" "$matcher" "$bin_path" "$bin_name" <<'PYEOF'
import json
import os
import shlex
import sys

settings_file = sys.argv[1]
hook_key = sys.argv[2]
matcher = sys.argv[3]
binary_path = sys.argv[4]
binary_name = sys.argv[5]

def matches_binary(command: str) -> bool:
    if not isinstance(command, str):
        return False
    cmd = command.strip()
    if not cmd:
        return False
    if binary_path and cmd == binary_path:
        return True
    try:
        parts = shlex.split(cmd)
    except Exception:
        parts = cmd.split()
    if not parts:
        return False
    first = parts[0]
    if binary_path and first == binary_path:
        return True
    if binary_path and os.path.isabs(first):
        try:
            if os.path.realpath(first) == os.path.realpath(binary_path):
                return True
        except Exception:
            pass
    return False

try:
    with open(settings_file, "r", encoding="utf-8") as f:
        settings = json.load(f)
except Exception:
    print("SKIP_INVALID_JSON")
    raise SystemExit(0)

if not isinstance(settings, dict):
    print("SKIP_INVALID_JSON")
    raise SystemExit(0)

hooks = settings.get("hooks")
if not isinstance(hooks, dict):
    print("NO_HOOKS")
    raise SystemExit(0)

entries = hooks.get(hook_key)
if not isinstance(entries, list):
    print("NO_HOOKS")
    raise SystemExit(0)

changed = False
new_entries = []
for entry in entries:
    if isinstance(entry, dict) and entry.get("matcher") == matcher:
        current_hooks = entry.get("hooks", [])
        if not isinstance(current_hooks, list):
            current_hooks = []
        kept = []
        for hook in current_hooks:
            if isinstance(hook, dict) and matches_binary(str(hook.get("command", ""))):
                changed = True
                continue
            kept.append(hook)
        if kept:
            entry["hooks"] = kept
            new_entries.append(entry)
        elif current_hooks:
            changed = True
    else:
        new_entries.append(entry)

if not changed:
    print("ALREADY_ABSENT")
    raise SystemExit(0)

hooks[hook_key] = new_entries
if not hooks[hook_key]:
    del hooks[hook_key]
if not hooks:
    settings.pop("hooks", None)

with open(settings_file, "w", encoding="utf-8") as f:
    json.dump(settings, f, indent=2)
    f.write("\n")

print("REMOVED")
PYEOF
  ); then
    warn "Failed to update hook settings: $settings_file"
    return 0
  fi

  case "$py_result" in
    REMOVED)
      ok "Removed installer hook from $settings_file"
      ;;
    ALREADY_ABSENT|NO_HOOKS)
      ;;
    SKIP_INVALID_JSON)
      warn "Skipping hook cleanup; invalid JSON in $settings_file"
      ;;
    *)
      warn "Unexpected hook cleanup result for $settings_file: $py_result"
      ;;
  esac
}

remove_installer_hooks() {
  if [ "$STATE_LOADED" -ne 1 ]; then
    return 0
  fi

  if [ -z "${PIAR_CLAUDE_HOOK_SETTINGS:-}" ] && [ -z "${PIAR_GEMINI_HOOK_SETTINGS:-}" ]; then
    return 0
  fi

  if [ -z "$(hook_binary_path)" ]; then
    warn "Skipping hook cleanup because installer binary path is missing from state"
    return 0
  fi

  if [ -n "${PIAR_CLAUDE_HOOK_SETTINGS:-}" ]; then
    if is_expected_hook_settings_path "$PIAR_CLAUDE_HOOK_SETTINGS" "claude"; then
      remove_hook_from_settings "$PIAR_CLAUDE_HOOK_SETTINGS" "PreToolUse" "Bash"
    else
      warn "Skipping unexpected Claude hook settings path: $PIAR_CLAUDE_HOOK_SETTINGS"
    fi
  fi
  if [ -n "${PIAR_GEMINI_HOOK_SETTINGS:-}" ]; then
    if is_expected_hook_settings_path "$PIAR_GEMINI_HOOK_SETTINGS" "gemini"; then
      remove_hook_from_settings "$PIAR_GEMINI_HOOK_SETTINGS" "BeforeTool" "run_shell_command"
    else
      warn "Skipping unexpected Gemini hook settings path: $PIAR_GEMINI_HOOK_SETTINGS"
    fi
  fi
}

remove_file_if_exists() {
  local path="$1"
  if [ -e "$path" ] || [ -L "$path" ]; then
    rm -f "$path"
    return 0
  fi
  return 1
}

remove_path_recursively() {
  local target="$1"
  if [ -z "$target" ]; then
    return 1
  fi
  if [ ! -e "$target" ] && [ ! -L "$target" ]; then
    return 0
  fi
  if [ -L "$target" ] || [ -f "$target" ] || [ -p "$target" ] || [ -S "$target" ] || [ -b "$target" ] || [ -c "$target" ]; then
    rm -f "$target"
    return $?
  fi
  if [ -d "$target" ]; then
    local child=""
    while IFS= read -r -d '' child; do
      remove_path_recursively "$child" || return 1
    done < <(find "$target" -mindepth 1 -maxdepth 1 -print0 2>/dev/null)
    rmdir "$target" 2>/dev/null || return 1
    return 0
  fi
  return 1
}

remove_path_entries() {
  if [ "$KEEP_PATH" -eq 1 ]; then
    return 0
  fi

  local touched=0
  for rc in "$HOME/.zshrc" "$HOME/.bashrc"; do
    [ -f "$rc" ] || continue
    grep -F "$PATH_MARKER" "$rc" >/dev/null 2>&1 || continue

    local tmp="${rc}.pi-uninstall.tmp"
    awk -v marker="$PATH_MARKER" 'index($0, marker) == 0 { print }' "$rc" > "$tmp"
    mv "$tmp" "$rc"
    touched=1
  done

  if [ "$touched" -eq 1 ]; then
    ok "Removed installer PATH entries"
  fi
}

fallback_binary_candidates() {
  cat <<EOF_CAND
$HOME/.local/bin/pi
$HOME/.local/bin/pi-rust
/usr/local/bin/pi
/usr/local/bin/pi-rust
EOF_CAND
}

remove_installed_binary() {
  local removed=0

  if [ -n "$PIAR_INSTALL_BIN" ] && [ -e "$PIAR_INSTALL_BIN" ]; then
    if is_rust_pi_binary "$PIAR_INSTALL_BIN"; then
      remove_file_if_exists "$PIAR_INSTALL_BIN" && removed=1
      ok "Removed Rust binary: $PIAR_INSTALL_BIN"
    else
      warn "Skipping non-Rust binary at recorded path: $PIAR_INSTALL_BIN"
    fi
  fi

  if [ "$removed" -eq 0 ]; then
    while IFS= read -r cand; do
      [ -n "$cand" ] || continue
      if [ -e "$cand" ] && is_rust_pi_binary "$cand"; then
        remove_file_if_exists "$cand" && removed=1
        ok "Removed Rust binary: $cand"
      fi
    done < <(fallback_binary_candidates)
  fi

  return 0
}

restore_moved_typescript_pi() {
  if [ "$NO_RESTORE_LEGACY" -eq 1 ]; then
    return 0
  fi

  if [ "${PIAR_ADOPTED_TYPESCRIPT:-0}" != "1" ]; then
    return 0
  fi

  if [ -z "$PIAR_LEGACY_MOVED_FROM" ] || [ -z "$PIAR_LEGACY_MOVED_TO" ]; then
    return 0
  fi

  if [ ! -e "$PIAR_LEGACY_MOVED_TO" ]; then
    warn "Legacy backup not found for restore: $PIAR_LEGACY_MOVED_TO"
    return 0
  fi

  if [ -e "$PIAR_LEGACY_MOVED_FROM" ]; then
    if is_rust_pi_binary "$PIAR_LEGACY_MOVED_FROM"; then
      remove_file_if_exists "$PIAR_LEGACY_MOVED_FROM" || true
    else
      warn "Skipping restore because destination already exists: $PIAR_LEGACY_MOVED_FROM"
      RESTORE_CONFLICT=1
      return 0
    fi
  fi

  mv "$PIAR_LEGACY_MOVED_TO" "$PIAR_LEGACY_MOVED_FROM"
  ok "Restored original pi binary: $PIAR_LEGACY_MOVED_FROM"
}

remove_legacy_alias() {
  local alias_path="$PIAR_LEGACY_ALIAS_PATH"
  if [ -z "$alias_path" ]; then
    return 0
  fi

  if [ ! -e "$alias_path" ]; then
    return 0
  fi

  if is_managed_alias "$alias_path"; then
    remove_file_if_exists "$alias_path" && ok "Removed legacy alias: $alias_path"
  else
    warn "Skipping non-managed alias file: $alias_path"
  fi
}

remove_installed_skills() {
  local codex_home="${CODEX_HOME:-$HOME/.codex}"
  local claude_dir="${PIAR_AGENT_SKILL_CLAUDE_PATH:-$HOME/.claude/skills/${AGENT_SKILL_NAME}}"
  local codex_dir="${PIAR_AGENT_SKILL_CODEX_PATH:-${codex_home}/skills/${AGENT_SKILL_NAME}}"

  local dir=""
  for dir in "$claude_dir" "$codex_dir"; do
    [ -n "$dir" ] || continue
    if ! is_expected_skill_directory "$dir"; then
      warn "Skipping unexpected skill directory path: $dir"
      continue
    fi
    local skill_file="$dir/SKILL.md"
    [ -f "$skill_file" ] || continue
    if ! is_managed_skill_file "$skill_file"; then
      warn "Skipping non-managed skill directory: $dir"
      continue
    fi

    remove_path_recursively "$dir" 2>/dev/null || true
    if [ ! -e "$dir" ]; then
      ok "Removed installer-managed skill: $dir"
    else
      warn "Failed to remove installer-managed skill: $dir"
    fi
  done
}

remove_state() {
  if [ "$RESTORE_CONFLICT" -eq 1 ]; then
    warn "Keeping installer state due restore conflict. Resolve and rerun uninstall."
    return 0
  fi

  if [ -f "$STATE_FILE" ]; then
    rm -f "$STATE_FILE"
    ok "Removed installer state file"
  fi

  if [ "$PURGE_STATE" -eq 1 ] || [ -z "$(ls -A "$STATE_DIR" 2>/dev/null || true)" ]; then
    rmdir "$STATE_DIR" 2>/dev/null || true
  fi
}

plan_summary() {
  [ "$QUIET" -eq 1 ] && return 0

  local lines=()
  if [ -n "$PIAR_INSTALL_BIN" ]; then
    lines+=("Rust binary: $PIAR_INSTALL_BIN")
  fi
  if [ -n "$PIAR_LEGACY_ALIAS_PATH" ]; then
    lines+=("Legacy alias: $PIAR_LEGACY_ALIAS_PATH")
  fi
  if [ -n "$PIAR_AGENT_SKILL_CLAUDE_PATH" ] || [ -n "$PIAR_AGENT_SKILL_CODEX_PATH" ]; then
    lines+=("Agent skills: remove installer-managed Claude/Codex skill dirs")
  fi
  if [ -n "$PIAR_CLAUDE_HOOK_SETTINGS" ] || [ -n "$PIAR_GEMINI_HOOK_SETTINGS" ]; then
    lines+=("Agent hooks: remove installer-managed Claude/Gemini hook entries")
  fi
  if [ -n "$PIAR_AGENT_SKILL_STATUS" ]; then
    lines+=("Recorded skill status: $PIAR_AGENT_SKILL_STATUS")
  fi
  if [ "${PIAR_ADOPTED_TYPESCRIPT:-0}" = "1" ] && [ "$NO_RESTORE_LEGACY" -eq 0 ]; then
    lines+=("Restore TS pi: ${PIAR_LEGACY_MOVED_TO:-<none>} -> ${PIAR_LEGACY_MOVED_FROM:-<none>}")
  fi
  if [ "$KEEP_PATH" -eq 0 ]; then
    lines+=("PATH cleanup: remove installer PATH marker lines")
  fi

  if [ ${#lines[@]} -eq 0 ]; then
    lines+=("No installer state detected; fallback cleanup will be attempted")
  fi

  if [ "$HAS_GUM" -eq 1 ] && [ "$NO_GUM" -eq 0 ]; then
    {
      gum style --foreground 196 --bold "Planned uninstall actions"
      echo ""
      for line in "${lines[@]}"; do
        gum style --foreground 245 "$line"
      done
    } | gum style --border normal --border-foreground 240 --padding "1 2"
  else
    echo -e "\033[1;31mPlanned uninstall actions\033[0m"
    for line in "${lines[@]}"; do
      echo -e "  \033[0;90m$line\033[0m"
    done
  fi
}

main() {
  show_header
  load_state
  plan_summary

  if ! prompt_confirm "Proceed with uninstall?" 1; then
    warn "Uninstall cancelled"
    exit 0
  fi

  remove_installed_binary
  remove_legacy_alias
  remove_installed_skills
  remove_installer_hooks
  restore_moved_typescript_pi
  remove_path_entries
  remove_state

  if [ "$QUIET" -eq 0 ]; then
    if [ "$HAS_GUM" -eq 1 ] && [ "$NO_GUM" -eq 0 ]; then
      gum style --foreground 42 --bold "pi uninstall complete"
    else
      echo -e "\033[1;32mpi uninstall complete\033[0m"
    fi
  fi
}

main "$@"
