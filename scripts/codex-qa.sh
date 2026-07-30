#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 LizardPope1101
# SPDX-License-Identifier: GPL-3.0-or-later
set -Eeuo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SESSION_NAME="${OSINT_FORGE_CODEX_QA_SESSION:-osint-forge-qa}"
EVIDENCE_ROOT="${OSINT_FORGE_QA_ROOT:-${HOME}/OSINT-Forge-QA}"
MODE="development"
COMMAND="start"

usage() {
    cat <<'EOF'
Usage:
  ./scripts/codex-qa.sh [development|release]
  ./scripts/codex-qa.sh status
  ./scripts/codex-qa.sh attach
  ./scripts/codex-qa.sh stop

Commands:
  development  Start autonomous development QA (default).
  release      Start autonomous release-candidate and live Debian QA.
  status       Show the active session and its latest recorded progress.
  attach       Attach to the persistent tmux session (detach with Ctrl-b d).
  stop         Interrupt Codex while preserving its evidence.

Environment:
  OSINT_FORGE_QA_ROOT           Evidence root (default: ~/OSINT-Forge-QA).
  OSINT_FORGE_CODEX_QA_SESSION  tmux session name (default: osint-forge-qa).
EOF
}

die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1"
}

validate_session_name() {
    [[ "$SESSION_NAME" =~ ^[A-Za-z0-9_.-]+$ ]] ||
        die "Unsafe tmux session name: $SESSION_NAME"
}

secure_path() {
    python3 - "$1" <<'PY'
import os
import pathlib
import stat
import sys

path = pathlib.Path(os.path.abspath(os.path.expanduser(sys.argv[1])))
cursor = pathlib.Path(path.anchor)
for part in path.parts[1:]:
    cursor /= part
    try:
        mode = cursor.lstat().st_mode
    except FileNotFoundError:
        continue
    if stat.S_ISLNK(mode):
        raise SystemExit(f"ERROR: path contains a symbolic link: {cursor}")
PY
}

latest_run_dir() {
    local sessions_dir="${EVIDENCE_ROOT}/codex-sessions"
    [[ -d "$sessions_dir" ]] || return 1
    find "$sessions_dir" -mindepth 1 -maxdepth 1 -type d -printf '%p\n' |
        sort |
        tail -n 1
}

show_status() {
    local run_dir=""
    if tmux has-session -t "=${SESSION_NAME}" 2>/dev/null; then
        printf 'Codex session: RUNNING (%s)\n' "$SESSION_NAME"
    else
        printf 'Codex session: STOPPED (%s)\n' "$SESSION_NAME"
    fi

    run_dir="$(latest_run_dir || true)"
    if [[ -z "$run_dir" ]]; then
        echo "No Codex QA run has been recorded."
        return
    fi

    printf 'Run directory:  %s\n' "$run_dir"
    if [[ -f "${run_dir}/metadata.txt" ]]; then
        sed -n '1,20p' "${run_dir}/metadata.txt"
    fi
    if [[ -f "${run_dir}/events.jsonl" ]]; then
        python3 - "${run_dir}/events.jsonl" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
last_message = None
terminal = None
for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
    try:
        event = json.loads(line)
    except json.JSONDecodeError:
        continue
    item = event.get("item", {})
    if item.get("type") == "agent_message":
        last_message = item.get("text")
    if event.get("type") in {"turn.completed", "turn.failed"}:
        terminal = event.get("type")

print(f"Codex event:    {terminal or 'in progress'}")
if last_message:
    compact = " ".join(last_message.split())
    print(f"Latest message: {compact[:500]}")
PY
    fi
    if [[ -f "${run_dir}/exit-code" ]]; then
        printf 'Exit code:      %s\n' "$(cat "${run_dir}/exit-code")"
    fi
    if [[ -f "${run_dir}/final-result.md" ]]; then
        printf 'Final result:   %s\n' "${run_dir}/final-result.md"
    fi
}

case "${1:-development}" in
    development|release)
        MODE="${1:-development}"
        ;;
    start)
        MODE="${2:-development}"
        [[ "$MODE" == "development" || "$MODE" == "release" ]] ||
            die "Unknown QA mode: $MODE"
        ;;
    status|attach|stop)
        COMMAND="$1"
        ;;
    -h|--help|help)
        usage
        exit 0
        ;;
    *)
        usage >&2
        die "Unknown command or mode: $1"
        ;;
esac

validate_session_name
require_command tmux
require_command python3

case "$COMMAND" in
    status)
        show_status
        exit 0
        ;;
    attach)
        tmux has-session -t "=${SESSION_NAME}" 2>/dev/null ||
            die "Codex QA session is not running: $SESSION_NAME"
        exec tmux attach-session -t "=${SESSION_NAME}"
        ;;
    stop)
        tmux has-session -t "=${SESSION_NAME}" 2>/dev/null ||
            die "Codex QA session is not running: $SESSION_NAME"
        tmux send-keys -t "=${SESSION_NAME}" C-c
        echo "Stop requested. Use '$0 status' to confirm shutdown."
        exit 0
        ;;
esac

require_command codex
require_command git
require_command gh
require_command sudo

[[ -f /etc/os-release ]] || die "Cannot identify the operating system."
# shellcheck disable=SC1091
source /etc/os-release
detected_os_id="${OSINT_FORGE_CODEX_QA_TEST_OS_ID:-${ID:-}}"
[[ "$detected_os_id" == "debian" ]] ||
    die "This launcher requires Debian; found: ${ID:-unknown}"

cd "$ROOT"
git rev-parse --is-inside-work-tree >/dev/null 2>&1 ||
    die "Not inside an OSINT Forge Git worktree."
[[ -z "$(git status --porcelain=v1)" ]] ||
    die "The Git worktree is not clean. Commit, stash, or remove local changes first."

codex login status >/dev/null 2>&1 ||
    die "Codex is not authenticated. Run: codex login"
gh auth status >/dev/null 2>&1 ||
    die "GitHub CLI is not authenticated. Run: gh auth login"

if tmux has-session -t "=${SESSION_NAME}" 2>/dev/null; then
    die "Codex QA is already running. Use '$0 status' or '$0 attach'."
fi

commit="$(git rev-parse HEAD)"
branch="$(git branch --show-current)"
version="$(./bin/osint --version)"

if [[ "$MODE" == "release" ]]; then
    [[ "$branch" == "main" ]] || die "Release QA must start from branch main; found: $branch"
    git fetch --quiet origin main
    remote_main="$(git rev-parse refs/remotes/origin/main)"
    [[ "$commit" == "$remote_main" ]] ||
        die "Local HEAD does not match origin/main (${commit} != ${remote_main})."
    sudo -n true >/dev/null 2>&1 ||
        die "Release QA requires configured passwordless sudo: sudo -n true"
fi

secure_path "$EVIDENCE_ROOT"
umask 077
mkdir -p "${EVIDENCE_ROOT}/codex-sessions"
chmod 700 "$EVIDENCE_ROOT" "${EVIDENCE_ROOT}/codex-sessions"

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="${EVIDENCE_ROOT}/codex-sessions/${stamp}-${MODE}-${commit:0:12}"
mkdir "$run_dir"
chmod 700 "$run_dir"

prompt_file="${run_dir}/prompt.md"
events_file="${run_dir}/events.jsonl"
final_file="${run_dir}/final-result.md"
runner_file="${run_dir}/run.sh"

cat >"$prompt_file" <<EOF
You are conducting owner-authorized ${MODE} QA for OSINT Forge on a dedicated
Debian testing VM.

Repository: ${ROOT}
Starting branch: ${branch}
Starting commit: ${commit}
Reported version: ${version}
Evidence directory: ${run_dir}

Read and obey AI_POLICY.md, docs/QA-HARNESS.md, docs/RELEASING.md,
CONTRIBUTING.md, and the authoritative Release Process wiki before acting.

Your task:

1. Inspect the exact repository state and identify the features, changed areas,
   open release tracker, known risks, and applicable test boundaries.
2. Design a comprehensive test plan for the task and candidate at hand. Include
   functional, regression, failure, interruption, resume, security, privacy,
   permission, packaging, installation, upgrade, uninstall, concurrency,
   documentation, and repository-integrity checks wherever applicable.
3. Run scripts/qa-harness.py with the ${MODE} profile and retain its complete
   evidence. In release mode, use origin/main as the candidate ref and perform
   the controlled live Debian tests required by policy.
4. Use only synthetic, reserved, loopback, operator-owned, or explicitly
   authorized targets. Never introduce real third-party personal data.
5. If a defect or meaningful uncertainty is discovered, create a regression
   test whenever technically practical, implement the smallest sound fix on a
   focused branch, open a pull request, wait for every required hosted check,
   merge only when green, update documentation, refresh main, and restart all
   affected validation against the new exact commit.
6. Add reasonable new tests whenever new issues, risks, or useful test ideas
   arise. Never alter an in-progress harness plan and reuse its old evidence;
   start a new bound run after changing code or the plan.
7. Preserve commands, timestamps, versions, outputs, exit codes, conclusions,
   and owner-only permissions. Never suppress or reinterpret a failure.
8. Do not create a version tag, publish a GitHub release, or announce a release.
   Testing and corrective patching are authorized; publication is not part of
   this run.
9. Finish with PASS or BLOCKED. State the exact final commit, tests completed,
   defects and fixes, remaining risks, evidence locations, and the safest next
   action. PASS is permitted only when every applicable gate succeeds.

Transport interruption is not test failure. Use the durable harness evidence
to resume verified completed gates, but rerun interrupted or unverifiable work.
EOF

cat >"${run_dir}/metadata.txt" <<EOF
Mode:           ${MODE}
Branch:         ${branch}
Commit:         ${commit}
Version:        ${version}
Started (UTC):  $(date -u +%Y-%m-%dT%H:%M:%SZ)
EOF

if [[ "$MODE" == "release" ]]; then
    codex_args=(
        exec
        --dangerously-bypass-approvals-and-sandbox
        --cd "$ROOT"
        --json
        --output-last-message "$final_file"
        -
    )
else
    codex_args=(
        --ask-for-approval never
        exec
        --sandbox workspace-write
        --cd "$ROOT"
        --json
        --output-last-message "$final_file"
        -
    )
fi

{
    echo '#!/usr/bin/env bash'
    echo 'set -Eeuo pipefail'
    printf 'cd %q\n' "$ROOT"
    printf 'events_file=%q\n' "$events_file"
    printf 'prompt_file=%q\n' "$prompt_file"
    printf 'exit_file=%q\n' "${run_dir}/exit-code"
    printf 'metadata_file=%q\n' "${run_dir}/metadata.txt"
    printf 'codex_cmd=('
    printf ' %q' codex "${codex_args[@]}"
    echo ' )'
    echo 'set +e'
    cat <<'RUNNER'
"${codex_cmd[@]}" <"$prompt_file" 2>&1 | tee "$events_file"
rc=${PIPESTATUS[0]}
set -e
printf "%s\n" "$rc" >"$exit_file"
printf "Completed (UTC): %s\n" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >>"$metadata_file"
exit "$rc"
RUNNER
} >"$runner_file"

chmod 600 "$prompt_file" "${run_dir}/metadata.txt"
chmod 700 "$runner_file"

tmux new-session -d -s "$SESSION_NAME" "$runner_file"

echo "Codex QA started."
echo "Mode:      $MODE"
echo "Commit:    $commit"
echo "Session:   $SESSION_NAME"
echo "Evidence:  $run_dir"
echo
echo "Watch live: $0 attach"
echo "Check:      $0 status"
echo "Detach:     Ctrl-b d"
