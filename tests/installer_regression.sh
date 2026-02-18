#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALLER="${ROOT}/install.sh"
UNINSTALLER="${ROOT}/uninstall.sh"
SKILL_SMOKE="${ROOT}/scripts/skill-smoke.sh"
WORK_ROOT="${TMPDIR:-/tmp}/pi-installer-regression-$(date -u +%Y%m%dT%H%M%SZ)-$$"

PASS_COUNT=0
FAIL_COUNT=0

mkdir -p "${WORK_ROOT}"

usage() {
  cat <<'USAGE'
Usage: tests/installer_regression.sh

Runs installer-focused regression checks for:
  - option parsing
  - checksum verification branches
  - sigstore/cosign verification branches
  - completion installation branches
USAGE
}

sha256_file() {
  local file="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file" | awk '{print $1}'
    return 0
  fi
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$file" | awk '{print $1}'
    return 0
  fi
  echo "missing sha256 tool (sha256sum or shasum)" >&2
  return 1
}

case_dir() {
  local name="$1"
  local dir="${WORK_ROOT}/${name}"
  mkdir -p "$dir/home" "$dir/state" "$dir/data" "$dir/config" "$dir/dest" "$dir/fixtures" "$dir/fakebin"
  printf '%s\n' "$dir"
}

write_existing_pi_stub() {
  local dir="$1"
  cat > "${dir}/fakebin/pi" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
if [ "${1:-}" = "--version" ]; then
  echo "pi 0.1.0 (existing-rust-stub)"
  exit 0
fi
echo "existing pi stub"
STUB
  chmod +x "${dir}/fakebin/pi"
}

write_cosign_stub() {
  local dir="$1"
  local mode="$2"
  cat > "${dir}/fakebin/cosign" <<EOF
#!/usr/bin/env bash
set -euo pipefail
if [ -n "\${COSIGN_LOG_PATH:-}" ]; then
  printf '%s\n' "\$*" >> "\${COSIGN_LOG_PATH}"
fi
if [ "${mode}" = "fail" ]; then
  echo "cosign fixture: forced failure" >&2
  exit 1
fi
exit 0
EOF
  chmod +x "${dir}/fakebin/cosign"
}

write_cp_fail_stub() {
  local dir="$1"
  cat > "${dir}/fakebin/cp" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
for arg in "$@"; do
  if [[ "$arg" == *"/skills/"* ]]; then
    echo "cp fixture: forced failure" >&2
    exit 1
  fi
done
/bin/cp "$@"
STUB
  chmod +x "${dir}/fakebin/cp"
}

write_uname_stub() {
  local dir="$1"
  local stub_os="$2"
  local stub_arch="$3"
  cat > "${dir}/fakebin/uname" <<EOF
#!/usr/bin/env bash
set -euo pipefail
if [ "\${1:-}" = "-s" ]; then
  echo "${stub_os}"
  exit 0
fi
if [ "\${1:-}" = "-m" ]; then
  echo "${stub_arch}"
  exit 0
fi
/usr/bin/uname "\$@"
EOF
  chmod +x "${dir}/fakebin/uname"
}

write_curl_artifact_stub() {
  local dir="$1"
  cat > "${dir}/fakebin/curl" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail

if [ -n "${CURL_LOG_PATH:-}" ]; then
  printf '%s\n' "$*" >> "${CURL_LOG_PATH}"
fi

output=""
is_head=0
args=("$@")
idx=0
while [ "$idx" -lt "${#args[@]}" ]; do
  arg="${args[$idx]}"
  case "$arg" in
    -I|-SI|-sI|-fsSLI)
      is_head=1
      ;;
    -o)
      idx=$((idx + 1))
      output="${args[$idx]}"
      ;;
  esac
  idx=$((idx + 1))
done

if [ "$is_head" -eq 1 ]; then
  exit 0
fi

url="${args[${#args[@]}-1]}"
if [ -n "$output" ] && [ -n "${STUB_ARTIFACT_SOURCE:-}" ]; then
  cp "${STUB_ARTIFACT_SOURCE}" "$output"
  exit 0
fi

if [ -n "$output" ] && [[ "$url" == file://* ]]; then
  cp "${url#file://}" "$output"
  exit 0
fi

if [ -n "$output" ]; then
  : > "$output"
  exit 0
fi

exit 0
STUB
  chmod +x "${dir}/fakebin/curl"
}

write_artifact_binary() {
  local path="$1"
  local mode="$2"
  cat > "$path" <<EOF
#!/usr/bin/env bash
set -euo pipefail
MODE="${mode}"

if [ "\${1:-}" = "--version" ]; then
  echo "pi 9.9.9 (fixture)"
  exit 0
fi

if [ "\${1:-}" = "completions" ]; then
  if [ "\${2:-}" = "--help" ]; then
    if [ "\${MODE}" = "unsupported" ]; then
      exit 1
    fi
    exit 0
  fi

  case "\${MODE}" in
    completion_fail)
      exit 1
      ;;
    completion_empty)
      exit 0
      ;;
    completion_ok)
      case "\${2:-}" in
        bash)
          echo "# bash completion for pi fixture"
          exit 0
          ;;
        zsh)
          echo "#compdef pi"
          exit 0
          ;;
        fish)
          echo "complete -c pi"
          exit 0
          ;;
        *)
          exit 1
          ;;
      esac
      ;;
    *)
      exit 1
      ;;
  esac
fi

if [ "\${1:-}" = "completion" ]; then
  if [ "\${2:-}" = "--help" ]; then
    exit 1
  fi
  exit 1
fi

exit 1
EOF
  chmod +x "$path"
}

run_installer() {
  local dir="$1"
  shift
  local out="${dir}/output.log"
  local rc_file="${dir}/exit_code"
  local path_value="${dir}/fakebin:/usr/bin:/bin"

  (
    set +e
    HOME="${dir}/home" \
    XDG_STATE_HOME="${dir}/state" \
    XDG_DATA_HOME="${dir}/data" \
    XDG_CONFIG_HOME="${dir}/config" \
    PATH="${path_value}" \
    SHELL="/bin/bash" \
    bash "${INSTALLER}" "$@" >"${out}" 2>&1
    echo "$?" > "${rc_file}"
  )
}

run_uninstaller() {
  local dir="$1"
  shift
  local out="${dir}/output.log"
  local rc_file="${dir}/exit_code"
  local path_value="${dir}/fakebin:/usr/bin:/bin"

  (
    set +e
    HOME="${dir}/home" \
    XDG_STATE_HOME="${dir}/state" \
    XDG_DATA_HOME="${dir}/data" \
    XDG_CONFIG_HOME="${dir}/config" \
    PATH="${path_value}" \
    SHELL="/bin/bash" \
    bash "${UNINSTALLER}" "$@" >"${out}" 2>&1
    echo "$?" > "${rc_file}"
  )
}

exit_code_of() {
  local dir="$1"
  cat "${dir}/exit_code"
}

assert_exit_code() {
  local dir="$1"
  local expected="$2"
  local actual
  actual="$(exit_code_of "$dir")"
  if [ "$actual" != "$expected" ]; then
    echo "expected exit ${expected}, got ${actual}" >&2
    echo "--- output (${dir}) ---" >&2
    cat "${dir}/output.log" >&2
    return 1
  fi
}

assert_output_contains() {
  local dir="$1"
  local needle="$2"
  if ! grep -Fq -- "$needle" "${dir}/output.log"; then
    echo "missing output text: ${needle}" >&2
    echo "--- output (${dir}) ---" >&2
    cat "${dir}/output.log" >&2
    return 1
  fi
}

run_test() {
  local name="$1"
  if "$name"; then
    PASS_COUNT=$((PASS_COUNT + 1))
    echo "[PASS] ${name}"
  else
    FAIL_COUNT=$((FAIL_COUNT + 1))
    echo "[FAIL] ${name}"
  fi
}

test_help_lists_installer_flags() {
  local dir
  dir="$(case_dir "help-flags")"
  write_existing_pi_stub "$dir"
  run_installer "$dir" --help
  assert_exit_code "$dir" 0
  assert_output_contains "$dir" "--artifact-url URL"
  assert_output_contains "$dir" "--checksum HEX"
  assert_output_contains "$dir" "--sigstore-bundle-url URL"
  assert_output_contains "$dir" "--completions SHELL"
  assert_output_contains "$dir" "--no-agent-skills"
}

test_skill_smoke_script_passes() {
  local dir
  dir="$(case_dir "skill-smoke-script")"

  if ! (
    cd "$ROOT"
    bash "$SKILL_SMOKE" > "${dir}/output.log" 2>&1
  ); then
    echo "skill smoke script failed" >&2
    cat "${dir}/output.log" >&2
    return 1
  fi
}

test_invalid_completions_value_fails() {
  local dir
  dir="$(case_dir "invalid-completions")"
  write_existing_pi_stub "$dir"
  run_installer "$dir" --completions nope --no-gum
  assert_exit_code "$dir" 1
  assert_output_contains "$dir" "Invalid --completions value"
}

test_unknown_option_fails() {
  local dir
  dir="$(case_dir "unknown-option")"
  write_existing_pi_stub "$dir"
  run_installer "$dir" --totally-unknown-flag
  assert_exit_code "$dir" 1
  assert_output_contains "$dir" "Unknown option"
}

test_missing_option_value_fails() {
  local dir
  dir="$(case_dir "missing-option-value")"
  write_existing_pi_stub "$dir"
  run_installer "$dir" --version
  assert_exit_code "$dir" 1
  assert_output_contains "$dir" "Option --version requires a value"
}

test_missing_option_value_when_next_arg_is_flag_fails() {
  local dir
  dir="$(case_dir "missing-option-value-next-flag")"
  write_existing_pi_stub "$dir"
  run_installer "$dir" --version --no-gum
  assert_exit_code "$dir" 1
  assert_output_contains "$dir" "Option --version requires a value"
}

test_custom_artifact_download_failure_does_not_source_fallback_without_version() {
  local dir missing_artifact
  dir="$(case_dir "custom-artifact-no-version-fallback")"
  write_existing_pi_stub "$dir"
  missing_artifact="${dir}/fixtures/missing-pi"

  run_installer "$dir" \
    --yes --no-gum --offline \
    --dest "${dir}/dest" \
    --artifact-url "file://${missing_artifact}" \
    --no-completions

  assert_exit_code "$dir" 1
  assert_output_contains "$dir" "Custom artifact download failed; cannot fall back to source without a release tag"
  assert_output_contains "$dir" "Pass --version vX.Y.Z with --artifact-url, or use --from-source directly"
}

test_offline_tarball_mode_installs_local_artifact() {
  local dir artifact offline_dir tarball checksum installed
  dir="$(case_dir "offline-tarball-mode")"
  write_existing_pi_stub "$dir"

  artifact="${dir}/fixtures/pi-fixture"
  write_artifact_binary "$artifact" "unsupported"

  offline_dir="${dir}/fixtures/offline-root"
  mkdir -p "$offline_dir"
  cp "$artifact" "${offline_dir}/pi"
  tar -czf "${dir}/fixtures/pi-offline.tar.gz" -C "$offline_dir" pi

  tarball="${dir}/fixtures/pi-offline.tar.gz"
  checksum="$(sha256_file "$tarball")"

  run_installer "$dir" \
    --yes --no-gum \
    --offline "$tarball" \
    --dest "${dir}/dest" \
    --checksum "$checksum" \
    --no-completions \
    --no-agent-skills

  installed="${dir}/dest/pi"

  assert_exit_code "$dir" 0
  assert_output_contains "$dir" "Offline artifact mode enabled"
  [ -x "$installed" ] || { echo "expected installed binary at ${installed}" >&2; return 1; }
}

test_offline_mode_blocks_network_artifact_urls() {
  local dir
  dir="$(case_dir "offline-blocks-network")"
  write_existing_pi_stub "$dir"

  run_installer "$dir" \
    --yes --no-gum \
    --offline \
    --version v9.9.9 \
    --dest "${dir}/dest" \
    --artifact-url "https://example.invalid/pi-fixture" \
    --checksum "0000000000000000000000000000000000000000000000000000000000000000" \
    --no-completions \
    --no-agent-skills

  assert_exit_code "$dir" 1
  assert_output_contains "$dir" "Offline mode requires a local --artifact-url path"
}

test_offline_relative_tarball_path_is_accepted() {
  local dir artifact tarball checksum installed
  dir="$(case_dir "offline-relative-tarball")"
  write_existing_pi_stub "$dir"

  artifact="${dir}/fixtures/pi-fixture"
  write_artifact_binary "$artifact" "unsupported"
  cp "$artifact" "${dir}/fixtures/pi"
  tar -czf "${dir}/fixtures/relative-offline.tar.gz" -C "${dir}/fixtures" pi

  tarball="fixtures/relative-offline.tar.gz"
  checksum="$(sha256_file "${dir}/fixtures/relative-offline.tar.gz")"

  (
    cd "$dir"
    run_installer "$dir" \
      --yes --no-gum \
      --offline "$tarball" \
      --dest "${dir}/dest" \
      --checksum "$checksum" \
      --no-completions \
      --no-agent-skills
  )

  installed="${dir}/dest/pi"
  assert_exit_code "$dir" 0
  [ -x "$installed" ] || { echo "expected installed binary at ${installed}" >&2; return 1; }
}

test_proxy_args_are_applied_to_curl_downloads() {
  local dir artifact checksum curl_log
  dir="$(case_dir "proxy-args-curl")"
  write_existing_pi_stub "$dir"
  write_curl_artifact_stub "$dir"

  artifact="${dir}/fixtures/pi-fixture"
  write_artifact_binary "$artifact" "unsupported"
  checksum="$(sha256_file "$artifact")"
  curl_log="${dir}/curl.log"

  HTTPS_PROXY="https://proxy.example.test:8443" \
  STUB_ARTIFACT_SOURCE="$artifact" \
  CURL_LOG_PATH="$curl_log" \
  run_installer "$dir" \
    --yes --no-gum \
    --version v9.9.9 \
    --dest "${dir}/dest" \
    --artifact-url "https://example.invalid/pi-fixture" \
    --checksum "$checksum" \
    --no-completions \
    --no-agent-skills

  assert_exit_code "$dir" 0
  assert_output_contains "$dir" "Using HTTPS proxy from environment"
  if ! grep -Fq -- "--proxy https://proxy.example.test:8443" "$curl_log"; then
    echo "expected --proxy arg in curl invocation" >&2
    cat "$curl_log" >&2
    return 1
  fi
}

test_linux_target_uses_musl_triple() {
  local dir artifact checksum curl_log
  dir="$(case_dir "linux-target-musl")"
  write_existing_pi_stub "$dir"
  write_uname_stub "$dir" "Linux" "x86_64"
  write_curl_artifact_stub "$dir"

  artifact="${dir}/fixtures/pi-fixture"
  write_artifact_binary "$artifact" "unsupported"
  checksum="$(sha256_file "$artifact")"
  curl_log="${dir}/curl.log"

  STUB_ARTIFACT_SOURCE="$artifact" \
  CURL_LOG_PATH="$curl_log" \
  run_installer "$dir" \
    --yes --no-gum \
    --version v9.9.9 \
    --dest "${dir}/dest" \
    --checksum "$checksum" \
    --no-completions \
    --no-agent-skills

  assert_exit_code "$dir" 0
  if ! grep -Fq "x86_64-unknown-linux-musl" "$curl_log"; then
    echo "expected musl target triple in artifact URL candidates" >&2
    cat "$curl_log" >&2
    return 1
  fi
}

test_wsl_detection_warning_is_emitted() {
  local dir artifact artifact_url checksum
  dir="$(case_dir "wsl-detection-warning")"
  write_existing_pi_stub "$dir"

  artifact="${dir}/fixtures/pi-fixture"
  write_artifact_binary "$artifact" "unsupported"
  artifact_url="file://${artifact}"
  checksum="$(sha256_file "$artifact")"

  PI_INSTALLER_TEST_FORCE_WSL=1 \
  run_installer "$dir" \
    --yes --no-gum --offline \
    --version v9.9.9 \
    --dest "${dir}/dest" \
    --artifact-url "${artifact_url}" \
    --checksum "${checksum}" \
    --no-completions \
    --no-agent-skills

  assert_exit_code "$dir" 0
  assert_output_contains "$dir" "WSL detected"
}

test_claude_hook_merge_ignores_substring_false_positive() {
  local dir artifact artifact_url checksum settings_file installed_bin
  dir="$(case_dir "claude-hook-substring-merge")"
  write_existing_pi_stub "$dir"

  settings_file="${dir}/home/.claude/settings.json"
  mkdir -p "$(dirname "$settings_file")"
  cat > "$settings_file" <<'JSON'
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "/usr/bin/pipx"
          }
        ]
      }
    ]
  }
}
JSON

  artifact="${dir}/fixtures/pi-fixture"
  write_artifact_binary "$artifact" "unsupported"
  artifact_url="file://${artifact}"
  checksum="$(sha256_file "$artifact")"

  run_installer "$dir" \
    --yes --no-gum --offline \
    --version v9.9.9 \
    --dest "${dir}/dest" \
    --artifact-url "${artifact_url}" \
    --checksum "${checksum}" \
    --no-completions \
    --no-agent-skills

  installed_bin="${dir}/dest/pi"
  assert_exit_code "$dir" 0
  assert_output_contains "$dir" "Claude hook: merged"
  grep -Fq "\"command\": \"${installed_bin}\"" "$settings_file" || {
    echo "expected Claude hook command for installed binary in settings" >&2
    cat "$settings_file" >&2
    return 1
  }
}

test_gemini_hook_merge_ignores_substring_false_positive() {
  local dir artifact artifact_url checksum settings_file installed_bin
  dir="$(case_dir "gemini-hook-substring-merge")"
  write_existing_pi_stub "$dir"

  settings_file="${dir}/home/.gemini/settings.json"
  mkdir -p "$(dirname "$settings_file")"
  cat > "$settings_file" <<'JSON'
{
  "hooks": {
    "BeforeTool": [
      {
        "matcher": "run_shell_command",
        "hooks": [
          {
            "name": "legacy-tool",
            "type": "command",
            "command": "/usr/bin/pipx",
            "timeout": 5000
          }
        ]
      }
    ]
  }
}
JSON

  artifact="${dir}/fixtures/pi-fixture"
  write_artifact_binary "$artifact" "unsupported"
  artifact_url="file://${artifact}"
  checksum="$(sha256_file "$artifact")"

  run_installer "$dir" \
    --yes --no-gum --offline \
    --version v9.9.9 \
    --dest "${dir}/dest" \
    --artifact-url "${artifact_url}" \
    --checksum "${checksum}" \
    --no-completions \
    --no-agent-skills

  installed_bin="${dir}/dest/pi"
  assert_exit_code "$dir" 0
  assert_output_contains "$dir" "Gemini hook: merged"
  grep -Fq "\"command\": \"${installed_bin}\"" "$settings_file" || {
    echo "expected Gemini hook command for installed binary in settings" >&2
    cat "$settings_file" >&2
    return 1
  }
}

test_claude_hook_merge_does_not_treat_bare_pi_as_installer_hook() {
  local dir artifact artifact_url checksum settings_file installed_bin
  dir="$(case_dir "claude-hook-bare-pi-merge")"
  write_existing_pi_stub "$dir"

  settings_file="${dir}/home/.claude/settings.json"
  mkdir -p "$(dirname "$settings_file")"
  cat > "$settings_file" <<'JSON'
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "pi --legacy-mode"
          }
        ]
      }
    ]
  }
}
JSON

  artifact="${dir}/fixtures/pi-fixture"
  write_artifact_binary "$artifact" "unsupported"
  artifact_url="file://${artifact}"
  checksum="$(sha256_file "$artifact")"

  run_installer "$dir" \
    --yes --no-gum --offline \
    --version v9.9.9 \
    --dest "${dir}/dest" \
    --artifact-url "${artifact_url}" \
    --checksum "${checksum}" \
    --no-completions \
    --no-agent-skills

  installed_bin="${dir}/dest/pi"
  assert_exit_code "$dir" 0
  assert_output_contains "$dir" "Claude hook: merged"
  grep -Fq "\"command\": \"${installed_bin}\"" "$settings_file" || {
    echo "expected installer Claude hook command to be added alongside bare pi command" >&2
    cat "$settings_file" >&2
    return 1
  }
  grep -Fq "\"command\": \"pi --legacy-mode\"" "$settings_file" || {
    echo "expected existing bare pi Claude hook command to remain" >&2
    cat "$settings_file" >&2
    return 1
  }
}

test_gemini_hook_merge_does_not_treat_bare_pi_as_installer_hook() {
  local dir artifact artifact_url checksum settings_file installed_bin
  dir="$(case_dir "gemini-hook-bare-pi-merge")"
  write_existing_pi_stub "$dir"

  settings_file="${dir}/home/.gemini/settings.json"
  mkdir -p "$(dirname "$settings_file")"
  cat > "$settings_file" <<'JSON'
{
  "hooks": {
    "BeforeTool": [
      {
        "matcher": "run_shell_command",
        "hooks": [
          {
            "name": "legacy-tool",
            "type": "command",
            "command": "pi --legacy-mode",
            "timeout": 5000
          }
        ]
      }
    ]
  }
}
JSON

  artifact="${dir}/fixtures/pi-fixture"
  write_artifact_binary "$artifact" "unsupported"
  artifact_url="file://${artifact}"
  checksum="$(sha256_file "$artifact")"

  run_installer "$dir" \
    --yes --no-gum --offline \
    --version v9.9.9 \
    --dest "${dir}/dest" \
    --artifact-url "${artifact_url}" \
    --checksum "${checksum}" \
    --no-completions \
    --no-agent-skills

  installed_bin="${dir}/dest/pi"
  assert_exit_code "$dir" 0
  assert_output_contains "$dir" "Gemini hook: merged"
  grep -Fq "\"command\": \"${installed_bin}\"" "$settings_file" || {
    echo "expected installer Gemini hook command to be added alongside bare pi command" >&2
    cat "$settings_file" >&2
    return 1
  }
  grep -Fq "\"command\": \"pi --legacy-mode\"" "$settings_file" || {
    echo "expected existing bare pi Gemini hook command to remain" >&2
    cat "$settings_file" >&2
    return 1
  }
}

test_hook_commands_use_absolute_path_for_relative_dest() {
  local dir artifact artifact_url checksum settings_file expected_bin
  dir="$(case_dir "hook-absolute-path-relative-dest")"
  write_existing_pi_stub "$dir"

  settings_file="${dir}/home/.claude/settings.json"
  mkdir -p "$(dirname "$settings_file")"

  artifact="${dir}/fixtures/pi-fixture"
  write_artifact_binary "$artifact" "unsupported"
  artifact_url="file://${artifact}"
  checksum="$(sha256_file "$artifact")"
  expected_bin="${dir}/relbin/pi"

  (
    cd "$dir"
    run_installer "$dir" \
      --yes --no-gum --offline \
      --version v9.9.9 \
      --dest "relbin" \
      --artifact-url "${artifact_url}" \
      --checksum "${checksum}" \
      --no-completions \
      --no-agent-skills
  )

  assert_exit_code "$dir" 0
  grep -Fq "\"command\": \"${expected_bin}\"" "$settings_file" || {
    echo "expected Claude hook command to use absolute install path for relative --dest" >&2
    cat "$settings_file" >&2
    return 1
  }
}

test_agent_skills_install_by_default() {
  local dir artifact artifact_url checksum claude_skill codex_skill
  dir="$(case_dir "agent-skills-default")"
  write_existing_pi_stub "$dir"

  artifact="${dir}/fixtures/pi-fixture"
  write_artifact_binary "$artifact" "unsupported"
  artifact_url="file://${artifact}"
  checksum="$(sha256_file "$artifact")"

  run_installer "$dir" \
    --yes --no-gum --offline \
    --version v9.9.9 \
    --dest "${dir}/dest" \
    --artifact-url "${artifact_url}" \
    --checksum "${checksum}" \
    --no-completions

  claude_skill="${dir}/home/.claude/skills/pi-agent-rust/SKILL.md"
  codex_skill="${dir}/home/.codex/skills/pi-agent-rust/SKILL.md"

  assert_exit_code "$dir" 0
  assert_output_contains "$dir" "Skills:    installed (claude,codex)"
  [ -f "$claude_skill" ] || { echo "missing Claude skill: $claude_skill" >&2; return 1; }
  [ -f "$codex_skill" ] || { echo "missing Codex skill: $codex_skill" >&2; return 1; }
  grep -Fq "pi_agent_rust installer managed skill" "$claude_skill" || {
    echo "missing managed marker in Claude skill" >&2
    return 1
  }
  grep -Fq "pi_agent_rust installer managed skill" "$codex_skill" || {
    echo "missing managed marker in Codex skill" >&2
    return 1
  }
  grep -Fq "## High-Value Commands" "$claude_skill" || {
    echo "installed skill should include high-value command section" >&2
    return 1
  }
}

test_no_agent_skills_opt_out() {
  local dir artifact artifact_url checksum
  dir="$(case_dir "agent-skills-opt-out")"
  write_existing_pi_stub "$dir"

  artifact="${dir}/fixtures/pi-fixture"
  write_artifact_binary "$artifact" "unsupported"
  artifact_url="file://${artifact}"
  checksum="$(sha256_file "$artifact")"

  run_installer "$dir" \
    --yes --no-gum --offline \
    --version v9.9.9 \
    --dest "${dir}/dest" \
    --artifact-url "${artifact_url}" \
    --checksum "${checksum}" \
    --no-agent-skills \
    --no-completions

  assert_exit_code "$dir" 0
  assert_output_contains "$dir" "Skills:    skipped (--no-agent-skills)"
  if [ -e "${dir}/home/.claude/skills/pi-agent-rust/SKILL.md" ]; then
    echo "Claude skill should not be installed when --no-agent-skills is used" >&2
    return 1
  fi
  if [ -e "${dir}/home/.codex/skills/pi-agent-rust/SKILL.md" ]; then
    echo "Codex skill should not be installed when --no-agent-skills is used" >&2
    return 1
  fi
}

test_existing_custom_skill_dirs_are_not_overwritten() {
  local dir artifact artifact_url checksum
  dir="$(case_dir "agent-skills-custom-preserve")"
  write_existing_pi_stub "$dir"

  mkdir -p "${dir}/home/.claude/skills/pi-agent-rust"
  mkdir -p "${dir}/home/.codex/skills/pi-agent-rust"
  printf 'custom\n' > "${dir}/home/.claude/skills/pi-agent-rust/NOT_A_SKILL.txt"
  printf 'custom\n' > "${dir}/home/.codex/skills/pi-agent-rust/NOT_A_SKILL.txt"

  artifact="${dir}/fixtures/pi-fixture"
  write_artifact_binary "$artifact" "unsupported"
  artifact_url="file://${artifact}"
  checksum="$(sha256_file "$artifact")"

  run_installer "$dir" \
    --yes --no-gum --offline \
    --version v9.9.9 \
    --dest "${dir}/dest" \
    --artifact-url "${artifact_url}" \
    --checksum "${checksum}" \
    --no-completions

  assert_exit_code "$dir" 0
  assert_output_contains "$dir" "Skills:    skipped (existing custom skill)"
  [ -f "${dir}/home/.claude/skills/pi-agent-rust/NOT_A_SKILL.txt" ] || {
    echo "Claude custom skill dir should be preserved" >&2
    return 1
  }
  [ -f "${dir}/home/.codex/skills/pi-agent-rust/NOT_A_SKILL.txt" ] || {
    echo "Codex custom skill dir should be preserved" >&2
    return 1
  }
}

test_skill_copy_failure_preserves_existing_managed_skills() {
  local dir artifact artifact_url checksum claude_skill codex_skill
  dir="$(case_dir "agent-skills-copy-fail-preserve-existing")"
  write_existing_pi_stub "$dir"
  write_cp_fail_stub "$dir"

  claude_skill="${dir}/home/.claude/skills/pi-agent-rust/SKILL.md"
  codex_skill="${dir}/home/.codex/skills/pi-agent-rust/SKILL.md"
  mkdir -p "$(dirname "$claude_skill")" "$(dirname "$codex_skill")"
  cat > "$claude_skill" <<'SKILL'
<!-- pi_agent_rust installer managed skill -->
# OLD CLAUDE SKILL
SKILL
  cat > "$codex_skill" <<'SKILL'
<!-- pi_agent_rust installer managed skill -->
# OLD CODEX SKILL
SKILL

  artifact="${dir}/fixtures/pi-fixture"
  write_artifact_binary "$artifact" "unsupported"
  artifact_url="file://${artifact}"
  checksum="$(sha256_file "$artifact")"

  run_installer "$dir" \
    --yes --no-gum --offline \
    --version v9.9.9 \
    --dest "${dir}/dest" \
    --artifact-url "${artifact_url}" \
    --checksum "${checksum}" \
    --no-completions

  assert_exit_code "$dir" 0
  assert_output_contains "$dir" "Skills:    failed (unable to write skill files)"
  grep -Fq "OLD CLAUDE SKILL" "$claude_skill" || {
    echo "existing managed Claude skill should be preserved when copy fails" >&2
    return 1
  }
  grep -Fq "OLD CODEX SKILL" "$codex_skill" || {
    echo "existing managed Codex skill should be preserved when copy fails" >&2
    return 1
  }
}

test_skill_custom_plus_copy_failure_reports_partial() {
  local dir artifact artifact_url checksum codex_custom
  dir="$(case_dir "agent-skills-custom-plus-copy-fail-partial")"
  write_existing_pi_stub "$dir"
  write_cp_fail_stub "$dir"

  codex_custom="${dir}/home/.codex/skills/pi-agent-rust/SKILL.md"
  mkdir -p "$(dirname "$codex_custom")"
  cat > "$codex_custom" <<'SKILL'
# Custom Codex skill without installer marker
SKILL

  artifact="${dir}/fixtures/pi-fixture"
  write_artifact_binary "$artifact" "unsupported"
  artifact_url="file://${artifact}"
  checksum="$(sha256_file "$artifact")"

  run_installer "$dir" \
    --yes --no-gum --offline \
    --version v9.9.9 \
    --dest "${dir}/dest" \
    --artifact-url "${artifact_url}" \
    --checksum "${checksum}" \
    --no-completions

  assert_exit_code "$dir" 0
  assert_output_contains "$dir" "Skills:    partial (custom skill kept; other install failed)"
  [ -f "$codex_custom" ] || {
    echo "custom Codex skill should be preserved" >&2
    return 1
  }
  if [ -f "${dir}/home/.claude/skills/pi-agent-rust/SKILL.md" ]; then
    echo "Claude skill should not be created when copy fails" >&2
    return 1
  fi
}

test_uninstall_removes_only_installer_managed_skills() {
  local dir managed_skill custom_skill
  dir="$(case_dir "uninstall-managed-skills-only")"

  managed_skill="${dir}/home/.claude/skills/pi-agent-rust/SKILL.md"
  custom_skill="${dir}/home/.codex/skills/pi-agent-rust/SKILL.md"
  mkdir -p "$(dirname "$managed_skill")" "$(dirname "$custom_skill")"

  cat > "$managed_skill" <<'SKILL'
<!-- pi_agent_rust installer managed skill -->
# Managed skill
SKILL
  cat > "$custom_skill" <<'SKILL'
# Custom local skill (no installer marker)
SKILL

  run_uninstaller "$dir" --yes --no-gum

  assert_exit_code "$dir" 0
  assert_output_contains "$dir" "Removed installer-managed skill: ${dir}/home/.claude/skills/pi-agent-rust"
  assert_output_contains "$dir" "Skipping non-managed skill directory: ${dir}/home/.codex/skills/pi-agent-rust"
  if [ -e "${dir}/home/.claude/skills/pi-agent-rust" ]; then
    echo "installer-managed Claude skill directory should be removed" >&2
    return 1
  fi
  if [ ! -f "${dir}/home/.codex/skills/pi-agent-rust/SKILL.md" ]; then
    echo "custom Codex skill directory should be preserved" >&2
    return 1
  fi
}

test_uninstall_uses_recorded_skill_paths() {
  local dir state_file recorded_codex managed_claude managed_codex
  dir="$(case_dir "uninstall-recorded-skill-paths")"
  recorded_codex="${dir}/home/custom-codex-home/skills/pi-agent-rust"

  managed_claude="${dir}/home/.claude/skills/pi-agent-rust/SKILL.md"
  managed_codex="${recorded_codex}/SKILL.md"
  mkdir -p "$(dirname "$managed_claude")" "$(dirname "$managed_codex")"

  cat > "$managed_claude" <<'SKILL'
<!-- pi_agent_rust installer managed skill -->
# Managed Claude skill
SKILL
  cat > "$managed_codex" <<'SKILL'
<!-- pi_agent_rust installer managed skill -->
# Managed Codex skill (recorded path)
SKILL

  state_file="${dir}/state/pi-agent-rust/install-state.env"
  mkdir -p "$(dirname "$state_file")"
  cat > "$state_file" <<STATE
PIAR_AGENT_SKILL_STATUS='installed (claude,codex)'
PIAR_AGENT_SKILL_CLAUDE_PATH='${dir}/home/.claude/skills/pi-agent-rust'
PIAR_AGENT_SKILL_CODEX_PATH='${recorded_codex}'
STATE

  run_uninstaller "$dir" --yes --no-gum

  assert_exit_code "$dir" 0
  assert_output_contains "$dir" "Removed installer-managed skill: ${dir}/home/.claude/skills/pi-agent-rust"
  assert_output_contains "$dir" "Removed installer-managed skill: ${recorded_codex}"
  if [ -e "${dir}/home/.claude/skills/pi-agent-rust" ]; then
    echo "installer-managed Claude skill should be removed" >&2
    return 1
  fi
  if [ -e "${recorded_codex}" ]; then
    echo "installer-managed Codex skill at recorded path should be removed" >&2
    return 1
  fi
}

test_uninstall_skips_unexpected_skill_paths() {
  local dir state_file unexpected_dir unexpected_skill
  dir="$(case_dir "uninstall-skip-unexpected-skill-path")"
  unexpected_dir="${dir}/home/custom/pi-agent-rust"
  unexpected_skill="${unexpected_dir}/SKILL.md"
  mkdir -p "$unexpected_dir"

  cat > "$unexpected_skill" <<'SKILL'
<!-- pi_agent_rust installer managed skill -->
# Managed marker on unexpected path
SKILL

  state_file="${dir}/state/pi-agent-rust/install-state.env"
  mkdir -p "$(dirname "$state_file")"
  cat > "$state_file" <<STATE
PIAR_AGENT_SKILL_CODEX_PATH='${unexpected_dir}'
STATE

  run_uninstaller "$dir" --yes --no-gum

  assert_exit_code "$dir" 0
  assert_output_contains "$dir" "Skipping unexpected skill directory path: ${unexpected_dir}"
  if [ ! -f "$unexpected_skill" ]; then
    echo "unexpected skill path should be preserved" >&2
    return 1
  fi
}

test_uninstall_removes_installer_managed_hook_entries() {
  local dir state_file claude_settings gemini_settings install_bin
  dir="$(case_dir "uninstall-remove-hooks")"
  install_bin="${dir}/dest/pi"

  claude_settings="${dir}/home/.claude/settings.json"
  gemini_settings="${dir}/home/.gemini/settings.json"
  mkdir -p "$(dirname "$claude_settings")" "$(dirname "$gemini_settings")"

  cat > "$claude_settings" <<JSON
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {"type": "command", "command": "${install_bin}"},
          {"type": "command", "command": "/usr/bin/pipx"},
          {"type": "command", "command": "pi --legacy-mode"}
        ]
      }
    ]
  }
}
JSON

  cat > "$gemini_settings" <<JSON
{
  "hooks": {
    "BeforeTool": [
      {
        "matcher": "run_shell_command",
        "hooks": [
          {"name":"pi-agent-rust","type":"command","command":"${install_bin}","timeout":5000},
          {"name":"legacy","type":"command","command":"/usr/bin/pipx","timeout":5000},
          {"name":"legacy-bare","type":"command","command":"pi --legacy-mode","timeout":5000}
        ]
      }
    ]
  }
}
JSON

  state_file="${dir}/state/pi-agent-rust/install-state.env"
  mkdir -p "$(dirname "$state_file")"
  cat > "$state_file" <<STATE
PIAR_INSTALL_BIN='${install_bin}'
PIAR_INSTALL_BIN_NAME='pi'
PIAR_CLAUDE_HOOK_SETTINGS='${claude_settings}'
PIAR_GEMINI_HOOK_SETTINGS='${gemini_settings}'
STATE

  run_uninstaller "$dir" --yes --no-gum

  assert_exit_code "$dir" 0
  assert_output_contains "$dir" "Removed installer hook from ${claude_settings}"
  assert_output_contains "$dir" "Removed installer hook from ${gemini_settings}"

  if grep -Fq "\"command\": \"${install_bin}\"" "$claude_settings"; then
    echo "expected installer Claude hook to be removed" >&2
    cat "$claude_settings" >&2
    return 1
  fi
  if ! grep -Fq "\"command\": \"/usr/bin/pipx\"" "$claude_settings"; then
    echo "expected non-installer Claude hook to remain" >&2
    cat "$claude_settings" >&2
    return 1
  fi
  if ! grep -Fq "\"command\": \"pi --legacy-mode\"" "$claude_settings"; then
    echo "expected bare pi Claude hook to remain" >&2
    cat "$claude_settings" >&2
    return 1
  fi

  if grep -Fq "\"command\": \"${install_bin}\"" "$gemini_settings"; then
    echo "expected installer Gemini hook to be removed" >&2
    cat "$gemini_settings" >&2
    return 1
  fi
  if ! grep -Fq "\"command\": \"/usr/bin/pipx\"" "$gemini_settings"; then
    echo "expected non-installer Gemini hook to remain" >&2
    cat "$gemini_settings" >&2
    return 1
  fi
  if ! grep -Fq "\"command\": \"pi --legacy-mode\"" "$gemini_settings"; then
    echo "expected bare pi Gemini hook to remain" >&2
    cat "$gemini_settings" >&2
    return 1
  fi
}

test_uninstall_does_not_touch_hooks_without_installer_state() {
  local dir claude_settings gemini_settings
  dir="$(case_dir "uninstall-no-state-hook-preserve")"

  claude_settings="${dir}/home/.claude/settings.json"
  gemini_settings="${dir}/home/.gemini/settings.json"
  mkdir -p "$(dirname "$claude_settings")" "$(dirname "$gemini_settings")"

  cat > "$claude_settings" <<'JSON'
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {"type":"command","command":"/usr/bin/pi"}
        ]
      }
    ]
  }
}
JSON

  cat > "$gemini_settings" <<'JSON'
{
  "hooks": {
    "BeforeTool": [
      {
        "matcher": "run_shell_command",
        "hooks": [
          {"name":"custom","type":"command","command":"/usr/bin/pi","timeout":5000}
        ]
      }
    ]
  }
}
JSON

  run_uninstaller "$dir" --yes --no-gum

  assert_exit_code "$dir" 0
  if ! grep -Fq "/usr/bin/pi" "$claude_settings"; then
    echo "expected Claude hook settings to remain untouched without installer state" >&2
    cat "$claude_settings" >&2
    return 1
  fi
  if ! grep -Fq "/usr/bin/pi" "$gemini_settings"; then
    echo "expected Gemini hook settings to remain untouched without installer state" >&2
    cat "$gemini_settings" >&2
    return 1
  fi
}

test_uninstall_skips_unexpected_hook_settings_paths() {
  local dir state_file unexpected_claude unexpected_gemini install_bin
  dir="$(case_dir "uninstall-skip-unexpected-hook-paths")"
  install_bin="${dir}/dest/pi"

  unexpected_claude="${dir}/home/custom/claude-settings.json"
  unexpected_gemini="${dir}/home/custom/gemini-settings.json"
  mkdir -p "$(dirname "$unexpected_claude")" "$(dirname "$unexpected_gemini")"

  cat > "$unexpected_claude" <<JSON
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {"type":"command","command":"${install_bin}"}
        ]
      }
    ]
  }
}
JSON

  cat > "$unexpected_gemini" <<JSON
{
  "hooks": {
    "BeforeTool": [
      {
        "matcher": "run_shell_command",
        "hooks": [
          {"name":"pi-agent-rust","type":"command","command":"${install_bin}","timeout":5000}
        ]
      }
    ]
  }
}
JSON

  state_file="${dir}/state/pi-agent-rust/install-state.env"
  mkdir -p "$(dirname "$state_file")"
  cat > "$state_file" <<STATE
PIAR_INSTALL_BIN='${install_bin}'
PIAR_INSTALL_BIN_NAME='pi'
PIAR_CLAUDE_HOOK_SETTINGS='${unexpected_claude}'
PIAR_GEMINI_HOOK_SETTINGS='${unexpected_gemini}'
STATE

  run_uninstaller "$dir" --yes --no-gum

  assert_exit_code "$dir" 0
  assert_output_contains "$dir" "Skipping unexpected Claude hook settings path: ${unexpected_claude}"
  assert_output_contains "$dir" "Skipping unexpected Gemini hook settings path: ${unexpected_gemini}"
  if ! grep -Fq "${install_bin}" "$unexpected_claude"; then
    echo "unexpected Claude hook settings should remain untouched" >&2
    cat "$unexpected_claude" >&2
    return 1
  fi
  if ! grep -Fq "${install_bin}" "$unexpected_gemini"; then
    echo "unexpected Gemini hook settings should remain untouched" >&2
    cat "$unexpected_gemini" >&2
    return 1
  fi
}

test_uninstall_skips_hook_cleanup_without_recorded_install_bin() {
  local dir state_file claude_settings gemini_settings install_bin
  dir="$(case_dir "uninstall-skip-hooks-missing-install-bin")"
  install_bin="${dir}/dest/pi"

  claude_settings="${dir}/home/.claude/settings.json"
  gemini_settings="${dir}/home/.gemini/settings.json"
  mkdir -p "$(dirname "$claude_settings")" "$(dirname "$gemini_settings")"

  cat > "$claude_settings" <<JSON
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {"type":"command","command":"${install_bin}"}
        ]
      }
    ]
  }
}
JSON

  cat > "$gemini_settings" <<JSON
{
  "hooks": {
    "BeforeTool": [
      {
        "matcher": "run_shell_command",
        "hooks": [
          {"name":"pi-agent-rust","type":"command","command":"${install_bin}","timeout":5000}
        ]
      }
    ]
  }
}
JSON

  state_file="${dir}/state/pi-agent-rust/install-state.env"
  mkdir -p "$(dirname "$state_file")"
  cat > "$state_file" <<STATE
PIAR_CLAUDE_HOOK_SETTINGS='${claude_settings}'
PIAR_GEMINI_HOOK_SETTINGS='${gemini_settings}'
STATE

  run_uninstaller "$dir" --yes --no-gum

  assert_exit_code "$dir" 0
  assert_output_contains "$dir" "Skipping hook cleanup because installer binary path is missing from state"
  if ! grep -Fq "${install_bin}" "$claude_settings"; then
    echo "Claude hook should remain when install bin path is missing" >&2
    cat "$claude_settings" >&2
    return 1
  fi
  if ! grep -Fq "${install_bin}" "$gemini_settings"; then
    echo "Gemini hook should remain when install bin path is missing" >&2
    cat "$gemini_settings" >&2
    return 1
  fi
}

test_checksum_inline_success() {
  local dir artifact artifact_url checksum
  dir="$(case_dir "checksum-inline-success")"
  write_existing_pi_stub "$dir"

  artifact="${dir}/fixtures/pi-fixture"
  write_artifact_binary "$artifact" "unsupported"
  artifact_url="file://${artifact}"
  checksum="$(sha256_file "$artifact")"

  run_installer "$dir" \
    --yes --no-gum --offline \
    --version v9.9.9 \
    --dest "${dir}/dest" \
    --artifact-url "${artifact_url}" \
    --checksum "${checksum}" \
    --no-completions

  assert_exit_code "$dir" 0
  assert_output_contains "$dir" "Checksum verified for"
  assert_output_contains "$dir" "Checksum:  verified (--checksum)"
}

test_checksum_mismatch_fails_hard() {
  local dir artifact artifact_url wrong_checksum
  dir="$(case_dir "checksum-mismatch")"
  write_existing_pi_stub "$dir"

  artifact="${dir}/fixtures/pi-fixture"
  write_artifact_binary "$artifact" "unsupported"
  artifact_url="file://${artifact}"
  wrong_checksum="0000000000000000000000000000000000000000000000000000000000000000"

  run_installer "$dir" \
    --yes --no-gum --offline \
    --version v9.9.9 \
    --dest "${dir}/dest" \
    --artifact-url "${artifact_url}" \
    --checksum "${wrong_checksum}" \
    --no-completions

  assert_exit_code "$dir" 1
  assert_output_contains "$dir" "Checksum mismatch"
  assert_output_contains "$dir" "Release checksum verification failed; aborting install"
}

test_checksum_missing_manifest_entry_fails_hard() {
  local dir artifact artifact_url checksum_manifest
  dir="$(case_dir "checksum-missing-entry")"
  write_existing_pi_stub "$dir"

  artifact="${dir}/fixtures/pi-fixture"
  write_artifact_binary "$artifact" "unsupported"
  artifact_url="file://${artifact}"

  checksum_manifest="${dir}/fixtures/custom.sha256"
  cat > "$checksum_manifest" <<'MANIFEST'
1111111111111111111111111111111111111111111111111111111111111111  other-artifact
2222222222222222222222222222222222222222222222222222222222222222  another-artifact
MANIFEST

  run_installer "$dir" \
    --yes --no-gum --offline \
    --version v9.9.9 \
    --dest "${dir}/dest" \
    --artifact-url "${artifact_url}" \
    --checksum-url "file://${checksum_manifest}" \
    --no-completions

  assert_exit_code "$dir" 1
  assert_output_contains "$dir" "No checksum entry found"
  assert_output_contains "$dir" "Release checksum verification failed; aborting install"
}

test_sigstore_bundle_unavailable_soft_skip() {
  local dir artifact artifact_url checksum
  dir="$(case_dir "sigstore-bundle-unavailable")"
  write_existing_pi_stub "$dir"
  write_cosign_stub "$dir" "pass"

  artifact="${dir}/fixtures/pi-fixture"
  write_artifact_binary "$artifact" "unsupported"
  artifact_url="file://${artifact}"
  checksum="$(sha256_file "$artifact")"

  run_installer "$dir" \
    --yes --no-gum --offline \
    --version v9.9.9 \
    --dest "${dir}/dest" \
    --artifact-url "${artifact_url}" \
    --checksum "${checksum}" \
    --no-completions

  assert_exit_code "$dir" 0
  assert_output_contains "$dir" "Offline mode: skipping signature verification without --sigstore-bundle-url"
  assert_output_contains "$dir" "Signature: skipped (offline; bundle not provided)"
}

test_sigstore_cosign_failure_fails_hard() {
  local dir artifact artifact_url bundle checksum
  dir="$(case_dir "sigstore-cosign-fail")"
  write_existing_pi_stub "$dir"
  write_cosign_stub "$dir" "fail"

  artifact="${dir}/fixtures/pi-fixture"
  write_artifact_binary "$artifact" "unsupported"
  artifact_url="file://${artifact}"
  checksum="$(sha256_file "$artifact")"
  bundle="${dir}/fixtures/pi-fixture.sigstore.json"
  printf '{"mediaType":"application/vnd.dev.sigstore.bundle+json;version=0.3"}\n' > "$bundle"

  run_installer "$dir" \
    --yes --no-gum --offline \
    --version v9.9.9 \
    --dest "${dir}/dest" \
    --artifact-url "${artifact_url}" \
    --checksum "${checksum}" \
    --sigstore-bundle-url "file://${bundle}" \
    --no-completions

  assert_exit_code "$dir" 1
  assert_output_contains "$dir" "Sigstore verification failed"
  assert_output_contains "$dir" "Release signature verification failed; aborting install"
}

test_sigstore_cosign_success() {
  local dir artifact artifact_url bundle checksum
  dir="$(case_dir "sigstore-cosign-success")"
  write_existing_pi_stub "$dir"
  write_cosign_stub "$dir" "pass"

  artifact="${dir}/fixtures/pi-fixture"
  write_artifact_binary "$artifact" "unsupported"
  artifact_url="file://${artifact}"
  checksum="$(sha256_file "$artifact")"
  bundle="${dir}/fixtures/pi-fixture.sigstore.json"
  printf '{"mediaType":"application/vnd.dev.sigstore.bundle+json;version=0.3"}\n' > "$bundle"

  run_installer "$dir" \
    --yes --no-gum --offline \
    --version v9.9.9 \
    --dest "${dir}/dest" \
    --artifact-url "${artifact_url}" \
    --checksum "${checksum}" \
    --sigstore-bundle-url "file://${bundle}" \
    --no-completions

  assert_exit_code "$dir" 0
  assert_output_contains "$dir" "Signature verified (cosign)"
  assert_output_contains "$dir" "Signature: verified"
}

test_completions_unsupported_build_soft_skip() {
  local dir artifact artifact_url checksum
  dir="$(case_dir "completions-unsupported")"
  write_existing_pi_stub "$dir"

  artifact="${dir}/fixtures/pi-fixture"
  write_artifact_binary "$artifact" "unsupported"
  artifact_url="file://${artifact}"
  checksum="$(sha256_file "$artifact")"

  run_installer "$dir" \
    --yes --no-gum --offline \
    --version v9.9.9 \
    --dest "${dir}/dest" \
    --artifact-url "${artifact_url}" \
    --checksum "${checksum}" \
    --completions bash

  assert_exit_code "$dir" 0
  assert_output_contains "$dir" "Shell completions: skipped (binary has no completion subcommand)"
  assert_output_contains "$dir" "Shell:     skipped (unsupported by this pi build)"
}

test_completions_generation_failure_recorded() {
  local dir artifact artifact_url checksum
  dir="$(case_dir "completions-generation-fail")"
  write_existing_pi_stub "$dir"

  artifact="${dir}/fixtures/pi-fixture"
  write_artifact_binary "$artifact" "completion_fail"
  artifact_url="file://${artifact}"
  checksum="$(sha256_file "$artifact")"

  run_installer "$dir" \
    --yes --no-gum --offline \
    --version v9.9.9 \
    --dest "${dir}/dest" \
    --artifact-url "${artifact_url}" \
    --checksum "${checksum}" \
    --completions bash

  assert_exit_code "$dir" 0
  assert_output_contains "$dir" "Failed to generate bash completions"
  assert_output_contains "$dir" "Shell:     failed (completion generation error)"
}

test_completions_success_writes_file() {
  local dir artifact artifact_url checksum completion_file
  dir="$(case_dir "completions-success")"
  write_existing_pi_stub "$dir"

  artifact="${dir}/fixtures/pi-fixture"
  write_artifact_binary "$artifact" "completion_ok"
  artifact_url="file://${artifact}"
  checksum="$(sha256_file "$artifact")"

  run_installer "$dir" \
    --yes --no-gum --offline \
    --version v9.9.9 \
    --dest "${dir}/dest" \
    --artifact-url "${artifact_url}" \
    --checksum "${checksum}" \
    --completions bash

  completion_file="${dir}/data/bash-completion/completions/pi"

  assert_exit_code "$dir" 0
  assert_output_contains "$dir" "Installed bash completions to"
  assert_output_contains "$dir" "Shell:     installed (bash)"
  if [ ! -f "$completion_file" ]; then
    echo "expected completion file: ${completion_file}" >&2
    return 1
  fi
  if ! grep -Fq "bash completion for pi fixture" "$completion_file"; then
    echo "completion file missing expected content: ${completion_file}" >&2
    cat "$completion_file" >&2
    return 1
  fi
}

main() {
  if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
    usage
    exit 0
  fi

  run_test test_help_lists_installer_flags
  run_test test_skill_smoke_script_passes
  run_test test_invalid_completions_value_fails
  run_test test_unknown_option_fails
  run_test test_missing_option_value_fails
  run_test test_missing_option_value_when_next_arg_is_flag_fails
  run_test test_custom_artifact_download_failure_does_not_source_fallback_without_version
  run_test test_offline_tarball_mode_installs_local_artifact
  run_test test_offline_mode_blocks_network_artifact_urls
  run_test test_offline_relative_tarball_path_is_accepted
  run_test test_proxy_args_are_applied_to_curl_downloads
  run_test test_linux_target_uses_musl_triple
  run_test test_wsl_detection_warning_is_emitted
  run_test test_claude_hook_merge_ignores_substring_false_positive
  run_test test_gemini_hook_merge_ignores_substring_false_positive
  run_test test_claude_hook_merge_does_not_treat_bare_pi_as_installer_hook
  run_test test_gemini_hook_merge_does_not_treat_bare_pi_as_installer_hook
  run_test test_hook_commands_use_absolute_path_for_relative_dest
  run_test test_agent_skills_install_by_default
  run_test test_no_agent_skills_opt_out
  run_test test_existing_custom_skill_dirs_are_not_overwritten
  run_test test_skill_copy_failure_preserves_existing_managed_skills
  run_test test_skill_custom_plus_copy_failure_reports_partial
  run_test test_uninstall_removes_only_installer_managed_skills
  run_test test_uninstall_uses_recorded_skill_paths
  run_test test_uninstall_skips_unexpected_skill_paths
  run_test test_uninstall_removes_installer_managed_hook_entries
  run_test test_uninstall_does_not_touch_hooks_without_installer_state
  run_test test_uninstall_skips_unexpected_hook_settings_paths
  run_test test_uninstall_skips_hook_cleanup_without_recorded_install_bin
  run_test test_checksum_inline_success
  run_test test_checksum_mismatch_fails_hard
  run_test test_checksum_missing_manifest_entry_fails_hard
  run_test test_sigstore_bundle_unavailable_soft_skip
  run_test test_sigstore_cosign_failure_fails_hard
  run_test test_sigstore_cosign_success
  run_test test_completions_unsupported_build_soft_skip
  run_test test_completions_generation_failure_recorded
  run_test test_completions_success_writes_file

  echo ""
  echo "work dir: ${WORK_ROOT}"
  echo "passed:   ${PASS_COUNT}"
  echo "failed:   ${FAIL_COUNT}"

  if [ "${FAIL_COUNT}" -gt 0 ]; then
    exit 1
  fi
}

main "$@"
