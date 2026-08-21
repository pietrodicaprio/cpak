#!/usr/bin/env bash

set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

fail() {
  printf 'phase5: %s\n' "$*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

assert_decision() {
  local expected_status="$1"
  local expected_action="$2"
  local output="$3"
  local actual_status="$4"
  python3 - "$expected_status" "$expected_action" "$output" "$actual_status" <<'PY'
import json
import pathlib
import sys

expected_status = int(sys.argv[1])
expected_action = sys.argv[2]
output = pathlib.Path(sys.argv[3])
document = json.loads(output.read_text(encoding="utf-8"))
actual_status = int(sys.argv[4])

if document.get("schema_version") != 1:
    raise SystemExit(f"unexpected decision schema: {document.get('schema_version')!r}")
final = document.get("final", {})
if final.get("exit_code") != expected_status or actual_status != expected_status:
    stderr = output.with_suffix(".err")
    detail = stderr.read_text(encoding="utf-8", errors="replace")[-4000:] if stderr.exists() else ""
    raise SystemExit(
        f"exit disagreement: process={actual_status}, decision={final.get('exit_code')}, "
        f"action={final.get('action')!r}, reason={final.get('reason_code')!r}, "
        f"expected={expected_status}; stderr tail={detail!r}"
    )
if final.get("action") != expected_action:
    raise SystemExit(f"final action={final.get('action')!r}, expected={expected_action!r}")
if not final.get("reason_code"):
    raise SystemExit("decision has no stable final reason code")
PY
}

assert_trust_envelope() {
  local expected_status="$1"
  local expected_action="$2"
  local expected_context="$3"
  local expected_operation="$4"
  local output="$5"
  local actual_status="$6"
  python3 - "$expected_status" "$expected_action" "$expected_context" "$expected_operation" "$output" "$actual_status" <<'PY'
import json
import pathlib
import sys

expected_status = int(sys.argv[1])
expected_action = sys.argv[2]
expected_context = sys.argv[3]
expected_operation = sys.argv[4]
output = pathlib.Path(sys.argv[5])
try:
    document = json.loads(output.read_text(encoding="utf-8"))
except (OSError, json.JSONDecodeError) as error:
    stderr = output.with_suffix(".err")
    detail = stderr.read_text(encoding="utf-8", errors="replace")[-4000:] if stderr.exists() else ""
    raise SystemExit(
        f"trust envelope unavailable: process={sys.argv[6]}, error={error}; stderr tail={detail!r}"
    ) from error
actual_status = int(sys.argv[6])

if document.get("schema_version") != 1:
    raise SystemExit(f"unexpected envelope schema: {document.get('schema_version')!r}")
trust = document.get("trust")
if not isinstance(trust, list) or len(trust) != 1:
    raise SystemExit(f"expected one trust result, got {trust!r}")
result = trust[0]
final = result.get("final", {})
if result.get("schema_version") != 1:
    raise SystemExit(f"unexpected result schema: {result.get('schema_version')!r}")
if result.get("context") != expected_context or result.get("operation") != expected_operation:
    raise SystemExit(
        f"decision context/operation={result.get('context')!r}/{result.get('operation')!r}, "
        f"expected={expected_context!r}/{expected_operation!r}"
    )
if final.get("exit_code") != expected_status or actual_status != expected_status:
    stderr = output.with_suffix(".err")
    detail = stderr.read_text(encoding="utf-8", errors="replace")[-4000:] if stderr.exists() else ""
    raise SystemExit(
        f"exit disagreement: process={actual_status}, decision={final.get('exit_code')}, "
        f"action={final.get('action')!r}, reason={final.get('reason_code')!r}, "
        f"expected={expected_status}; stderr tail={detail!r}"
    )
if final.get("action") != expected_action or not final.get("reason_code"):
    raise SystemExit(f"unexpected final decision: {final!r}")
PY
}

assert_human_trust_projection() {
  local machine_output="$1"
  local human_output="$2"
  local actual_status="$3"
  python3 - "$machine_output" "$human_output" "$actual_status" <<'PY'
import json
import pathlib
import sys

machine = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
human = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8", errors="replace")
actual_status = int(sys.argv[3])
result = machine.get("trust", [{}])[0]
final = result.get("final", {})
if actual_status != final.get("exit_code"):
    raise SystemExit(
        f"human/JSON exit disagreement: human={actual_status}, JSON={final.get('exit_code')!r}"
    )

markers = (
    "Application trust for ",
    "Publisher:",
    "Evidence:",
    "Trust:",
    "Reputation:",
    "Policy:",
)
lines = [line for line in human.splitlines() if any(marker in line for marker in markers)]
for marker in markers:
    matching = [line for line in lines if marker in line]
    if len(matching) != 1:
        raise SystemExit(f"human projection has {len(matching)} lines for {marker!r}: {lines!r}")
projection = "\n".join(lines)
for expected in (str(final.get("action", "")), str(final.get("reason_code", ""))):
    if not expected or expected not in projection:
        raise SystemExit(f"human projection omitted final value {expected!r}: {projection!r}")
if "\x00" in projection or "\x1b" in projection:
    raise SystemExit(f"human projection contains terminal controls: {projection!r}")
lower = projection.lower()
for forbidden in ("software is safe", "application is safe", "trusted application", "trusted publisher"):
    if forbidden in lower:
        raise SystemExit(f"human projection makes a positive safety claim {forbidden!r}: {projection!r}")
for line in lines:
    if len(line.encode("utf-8")) > 1024:
        raise SystemExit(f"human projection line is unbounded: {len(line.encode('utf-8'))} bytes")
PY
}

verify_x509() {
  local expected_status="$1"
  local expected_action="$2"
  local output="$phase5_dir/decision-$expected_status-$expected_action.json"
  local status
  set +e
  "$phase5_bin_dir/cpak" verify-signature "$phase5_dir/state.cms" \
    --state "$phase5_dir/state" --evidence-kind x509-cms --json >"$output"
  status=$?
  set -e
  assert_decision "$expected_status" "$expected_action" "$output" "$status"
}

import_reputation_status() {
  local sequence="$1"
  local status="$2"
  local publisher_id="$3"
  local payload="$phase5_dir/reputation-payload-$sequence.json"
  local snapshot="$phase5_dir/reputation-snapshot-$sequence.json"

  python3 - "$payload" "$publisher_id" "$sequence" "$status" <<'PY'
import datetime
import json
import pathlib
import sys

now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
payload = {
    "sequence": int(sys.argv[3]),
    "issued_at": (now - datetime.timedelta(minutes=1)).isoformat().replace("+00:00", "Z"),
    "expires_at": (now + datetime.timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
    "entries": [{
        "publisher_id": sys.argv[2],
        "status": sys.argv[4],
        "reason_code": "phase5-harness-" + sys.argv[4],
    }],
}

pathlib.Path(sys.argv[1]).write_text(json.dumps(payload, separators=(",", ":")) + "\n", encoding="utf-8")
PY
  "$phase5_bin_dir/cpak-sign" reputation-sign \
    --authority "$phase5_dir/reputation-provider.json" \
    --key "$phase5_dir/reputation-provider-key.pem" \
    --key-passphrase-file "$phase5_dir/passphrase" \
    --payload "$payload" \
    --output "$snapshot"

  local snapshot_fingerprint
  snapshot_fingerprint="$(sha256sum "$snapshot" | awk '{print $1}')"
  "$phase5_bin_dir/cpak" system reputation-import "$snapshot" \
    --fingerprint "$snapshot_fingerprint" --yes
}

run_via_frontend() {
  local frontend="$1"
  shift
  runuser -u "$frontend_user" -- env \
    HOME="$HOME" \
    XDG_CONFIG_HOME="$XDG_CONFIG_HOME" \
    XDG_DATA_HOME="$XDG_DATA_HOME" \
    XDG_STATE_HOME="$XDG_STATE_HOME" \
    CPAK_INSTALLATION_PATH="$CPAK_INSTALLATION_PATH" \
    PATH="$phase5_bin_dir/frontend-$frontend" \
    "$phase5_bin_dir/cpak" "$@"
}

write_frontend_policy() {
  local arguments="$1"
  local sudo_arguments="${arguments//:/\\:}"
  printf '%s ALL=(root) NOPASSWD: %s %s\n' \
    "$frontend_user" "$phase5_bin_dir/cpak" "$sudo_arguments" \
    > /etc/sudoers.d/cpak-phase5-frontends
  chmod 0440 /etc/sudoers.d/cpak-phase5-frontends
  visudo -cf /etc/sudoers.d/cpak-phase5-frontends >/dev/null

  printf 'permit nopass %s as root cmd %s args %s\n' \
    "$frontend_user" "$phase5_bin_dir/cpak" "$arguments" \
    > /etc/doas.conf
  chmod 0400 /etc/doas.conf
}

exercise_root_frontend() {
  local frontend="$1"
  local root_fingerprint="$2"
  local add_arguments="system trust-root-add $phase5_dir/pki/root.pem --purpose code-signing --fingerprint $root_fingerprint --yes"
  write_frontend_policy "$add_arguments"
  run_via_frontend "$frontend" system trust-root-add "$phase5_dir/pki/root.pem" \
    --purpose code-signing --fingerprint "$root_fingerprint" --yes
  verify_x509 0 allow

  local remove_arguments="system trust-root-remove $root_fingerprint --purpose code-signing --yes"
  write_frontend_policy "$remove_arguments"
  run_via_frontend "$frontend" system trust-root-remove "$root_fingerprint" \
    --purpose code-signing --yes
  verify_x509 21 invalid
  printf 'phase5: %s trust-root frontend lifecycle passed\n' "$frontend"
}

exercise_reputation_frontend() {
  local frontend="$1"
  local publisher_id="$2"
  local provider_key="$3"
  local snapshot_fingerprint="$4"
  local arguments="system reputation-provider-set $phase5_dir/reputation-provider.json --fingerprint $provider_key --yes"
  write_frontend_policy "$arguments"
  run_via_frontend "$frontend" system reputation-provider-set \
    "$phase5_dir/reputation-provider.json" --fingerprint "$provider_key" --yes

  arguments="system reputation-import $phase5_dir/reputation-snapshot.json --fingerprint $snapshot_fingerprint --yes"
  write_frontend_policy "$arguments"
  run_via_frontend "$frontend" system reputation-import \
    "$phase5_dir/reputation-snapshot.json" --fingerprint "$snapshot_fingerprint" --yes
  run_via_frontend "$frontend" system reputation-check "$publisher_id" | \
    grep -F 'established' >/dev/null

  arguments="system reputation-provider-clear --fingerprint $provider_key --yes"
  write_frontend_policy "$arguments"
  run_via_frontend "$frontend" system reputation-provider-clear \
    --fingerprint "$provider_key" --yes
  printf 'phase5: %s reputation frontend lifecycle passed\n' "$frontend"
}

run_graphical_enrolment() {
  local origin="$1"
  local display_number=":99"
  local install_pid=""
  local status window_id=""

  Xvfb "$display_number" -screen 0 1024x768x24 -nolisten tcp -extension MIT-SHM \
    >"$phase5_dir/xvfb.log" 2>&1 &
  xvfb_pid=$!
  for _ in {1..100}; do
    if DISPLAY="$display_number" xwininfo -root >/dev/null 2>&1; then
      break
    fi
    if ! kill -0 "$xvfb_pid" 2>/dev/null; then
      python3 - "$phase5_dir/xvfb.log" <<'PY'
import pathlib
import sys
print(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace")[-4000:], file=sys.stderr)
PY
      fail "the graphical test display stopped"
    fi
    sleep 0.1
  done
  if ! DISPLAY="$display_number" xwininfo -root >/dev/null 2>&1; then
    python3 - "$phase5_dir/xvfb.log" <<'PY'
import pathlib
import sys
print(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace")[-4000:], file=sys.stderr)
PY
    fail "the graphical test display did not become ready"
  fi

  # Xvfb is a bare X server with no window manager. The builtin reputation
  # prompt sizes and paints itself only after the first size.Event, which the
  # shiny x11driver derives from a ConfigureNotify. A top-level window mapped at
  # its final size with no WM never gets that reconfiguration, so the dialog
  # stays zero-sized and the click hit-tests against an empty layout. A
  # reparenting WM reconfigures the mapped window and delivers the size.Event.
  DISPLAY="$display_number" openbox --sm-disable \
    >"$phase5_dir/openbox.log" 2>&1 &
  wm_pid=$!
  for _ in {1..100}; do
    if DISPLAY="$display_number" xprop -root _NET_SUPPORTING_WM_CHECK 2>/dev/null | \
      grep -q 'window id'; then
      break
    fi
    if ! kill -0 "$wm_pid" 2>/dev/null; then
      python3 - "$phase5_dir/openbox.log" <<'PY'
import pathlib
import sys
print(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace")[-4000:], file=sys.stderr)
PY
      fail "the graphical window manager stopped"
    fi
    sleep 0.1
  done
  if ! DISPLAY="$display_number" xprop -root _NET_SUPPORTING_WM_CHECK 2>/dev/null | \
    grep -q 'window id'; then
    python3 - "$phase5_dir/openbox.log" <<'PY'
import pathlib
import sys
print(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace")[-4000:], file=sys.stderr)
PY
    fail "the graphical window manager did not become ready"
  fi

  DISPLAY="$display_number" "$phase5_bin_dir/cpak" install \
    --branch main --yes --graphical "$origin" \
    >"$phase5_dir/install-graphical.log" 2>&1 &
  install_pid=$!
  # The reparenting WM wraps the dialog in a same-sized frame that carries no
  # name, so a geometry-only match selects that frame and the click lands on a
  # window Shiny never selected pointer motion on. Match the client by its
  # stable WM_NAME (the NewWindow title) as well as its size.
  for _ in {1..100}; do
    window_id="$(DISPLAY="$display_number" xwininfo -root -tree 2>/dev/null | \
      awk '$1 ~ /^0x[0-9a-f]+$/ && /Publisher reputation/ && /620x540/ && !found {print $1; found=1}')"
    if [[ -n "$window_id" ]]; then
      break
    fi
    kill -0 "$install_pid" 2>/dev/null || break
    sleep 0.1
  done
  if [[ -z "$window_id" ]]; then
    DISPLAY="$display_number" xwininfo -root -tree >&2 || true
    fail "the publisher reputation window did not appear"
  fi

  DISPLAY="$display_number" "$phase5_bin_dir/cpak-phase5-x11-click" \
    --window "$window_id" --x 429 --y 479
  for _ in {1..300}; do
    kill -0 "$install_pid" 2>/dev/null || break
    sleep 0.1
  done
  if kill -0 "$install_pid" 2>/dev/null; then
    DISPLAY="$display_number" xprop -root _NET_SUPPORTING_WM_CHECK >&2 || true
    DISPLAY="$display_number" xwininfo -root -tree >&2 || true
    kill "$install_pid" 2>/dev/null || true
    wait "$install_pid" 2>/dev/null || true
    python3 - "$phase5_dir/install-graphical.log" <<'PY'
import pathlib
import sys

print(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace")[-4000:], file=sys.stderr)
PY
    fail "the graphical enrolment did not finish after confirmation"
  fi
  set +e
  wait "$install_pid"
  status=$?
  set -e
  kill "$wm_pid" 2>/dev/null || true
  wait "$wm_pid" 2>/dev/null || true
  wm_pid=""
  kill "$xvfb_pid" 2>/dev/null || true
  wait "$xvfb_pid" 2>/dev/null || true
  xvfb_pid=""

  [[ "$status" -eq 0 ]] || fail "graphical enrolment exited $status"
  grep -F 'confirmation accepted' "$phase5_dir/install-graphical.log" >/dev/null || \
    fail "graphical result did not record accepted confirmation"
  printf 'phase5: real graphical reputation confirmation passed\n'
}

start_phase5_service() {
  local origin="$1"
  local output="$2"
  local error_output="$3"

  : >"$output"
  : >"$error_output"
  "$phase5_bin_dir/cpak" run --branch main "$origin" phase5-fixture service \
    >"$output" 2>"$error_output" &
  service_pid=$!
  service_origin="$origin"

  for _ in {1..200}; do
    if grep -Fx 'phase5 service ready' "$output" >/dev/null 2>&1; then
      kill -0 "$service_pid" 2>/dev/null || fail "the Phase 5 service exited after reporting readiness"
      return
    fi
    kill -0 "$service_pid" 2>/dev/null || {
      tail -n 80 "$output" >&2 || true
      tail -n 80 "$error_output" >&2 || true
      fail "the Phase 5 service exited before reporting readiness"
    }
    sleep 0.05
  done
  tail -n 80 "$output" >&2 || true
  tail -n 80 "$error_output" >&2 || true
  fail "the Phase 5 service did not report readiness"
}

stop_phase5_service() {
  local origin="$1"

  timeout 20 "$phase5_bin_dir/cpak" stop --branch main "$origin"
  for _ in {1..200}; do
    kill -0 "$service_pid" 2>/dev/null || break
    sleep 0.05
  done
  if kill -0 "$service_pid" 2>/dev/null; then
    fail "the Phase 5 service did not stop"
  fi
  wait "$service_pid" 2>/dev/null || true
  service_pid=""
  service_origin=""
}

run_service_lifecycle() {
  local origin="$1"
  local host owner repository extra
  IFS=/ read -r host owner repository extra <<<"$origin"
  [[ -n "$host" && -n "$owner" && -n "$repository" && -z "$extra" ]] || \
    fail "the service lifecycle received an invalid origin"

  start_phase5_service "$origin" "$phase5_dir/service-first.out" "$phase5_dir/service-first.err"

  local override_dir="$HOME/.config/cpak/overrides/$host/$owner/$repository/main"
  local override_file="$override_dir/cpak.json"
  mkdir -p "$override_dir"
  (
    umask 077
    printf '{"network":true}\n' >"$override_file"
  )
  chmod 0600 "$override_file"

  local status
  set +e
  "$phase5_bin_dir/cpak" system explain "$origin" --json \
    >"$phase5_dir/explain-service-mismatch.json" 2>"$phase5_dir/explain-service-mismatch.err"
  status=$?
  set -e
  python3 - "$phase5_dir/explain-service-mismatch.json" "$status" <<'PY'
import json
import pathlib
import sys

document = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
status = int(sys.argv[2])
trust = document.get("trust", {})
final = trust.get("final", {})
if document.get("schema_version") != 1 or trust.get("operation") != "explain":
    raise SystemExit(f"unexpected service mismatch envelope: {document!r}")
if status != 21 or final.get("exit_code") != 21 or final.get("action") != "invalid":
    raise SystemExit(f"service mismatch exit disagreement: process={status}, final={final!r}")
if final.get("reason_code") != "runtime-integrity-mismatch":
    raise SystemExit(f"unexpected service mismatch reason: {final!r}")
PY

  set +e
  timeout 20 "$phase5_bin_dir/cpak" run --branch main "$origin" phase5-fixture \
    </dev/null >"$phase5_dir/service-refused.out" 2>"$phase5_dir/service-refused.err"
  status=$?
  set -e
  [[ "$status" -ne 0 && "$status" -ne 124 ]] || \
    fail "a changed service launch was not refused before container reuse"
  grep -F 'does not match the integrity anchor it was enrolled with' \
    "$phase5_dir/service-refused.err" >/dev/null || \
    fail "the changed service launch did not report its anchor mismatch"
  kill -0 "$service_pid" 2>/dev/null || \
    fail "a future service refusal terminated the already running process"

  stop_phase5_service "$origin"

  set +e
  timeout 20 "$phase5_bin_dir/cpak" run --branch main "$origin" phase5-fixture service \
    </dev/null >"$phase5_dir/service-restart-refused.out" 2>"$phase5_dir/service-restart-refused.err"
  status=$?
  set -e
  [[ "$status" -ne 0 && "$status" -ne 124 ]] || \
    fail "the changed service restart was not refused"
  grep -F 'does not match the integrity anchor it was enrolled with' \
    "$phase5_dir/service-restart-refused.err" >/dev/null || \
    fail "the changed service restart did not report its anchor mismatch"

  rm -f -- "$override_file"
  start_phase5_service "$origin" "$phase5_dir/service-recovered.out" "$phase5_dir/service-recovered.err"
  stop_phase5_service "$origin"

  printf 'phase5: systemd-equivalent service start, refusal, recovery, and restart passed\n'
}

write_x509_generation() {
  local generation="$1"
  local origin="$2"
  local image_digest="$3"
  local publisher="${4:-publisher}"

  "$phase5_bin_dir/cpak-sign" state \
    --manifest "$phase5_dir/cpak.json" \
    --origin "$origin" \
    --image-digest "$image_digest" \
    --generation "$generation" \
    --output "$phase5_dir/state-$generation"
  "$phase5_bin_dir/cpak-sign" x509-sign \
    --state "$phase5_dir/state-$generation" \
    --certificate "$phase5_dir/pki/$publisher.pem" \
    --chain "$phase5_dir/pki/$publisher-chain.pem" \
    --key "$phase5_dir/pki/$publisher-key.pem" \
    --key-passphrase-file "$phase5_dir/passphrase" \
    --output "$phase5_dir/state-$generation.cms"
  printf '%s\n' "$generation" >"$phase5_dir/generation"
}

write_reputation_policy() {
  local output_path="$1"
  local publisher_id="$2"
  local mode="$3"
  case "$mode" in
    off | audit | warn | require-established) ;;
    *) fail "unsupported reputation mode: $mode" ;;
  esac
  python3 - "$output_path" "$publisher_id" "$mode" <<'PY'
import json
import pathlib
import sys

mode = sys.argv[3]
reputation = {"mode": mode}
if mode != "off":
    reputation["provider_id"] = "cpak-phase5"
policy = {
    "abi": 2,
    "require_publisher": True,
    "require_approval": False,
    "approved_publisher_ids": [sys.argv[2]],
    "x509": {"revocation": "allow-unknown"},
    "reputation": reputation,
}
pathlib.Path(sys.argv[1]).write_text(json.dumps(policy) + "\n", encoding="utf-8")
PY
}

run_reputation_outage_matrix() {
  local origin="$1"
  local publisher_id="$2"
  local image_digest="$3"
  local generation mode expected_status expected_action expected_reputation label output

  while read -r generation mode expected_status expected_action expected_reputation; do
    "$phase5_bin_dir/cpak" remove --branch main "$origin"
    write_x509_generation "$generation" "$origin" "$image_digest"
    write_reputation_policy "$phase5_dir/trust-policy-$mode.json" "$publisher_id" "$mode"
    "$phase5_bin_dir/cpak" system set-trust "$phase5_dir/trust-policy-$mode.json"

    label="reputation-outage-$mode"
    run_install_decision "$expected_status" "$expected_action" "$label" "$origin"
    output="$phase5_dir/install-$label.json"
    python3 - "$output" "$expected_reputation" <<'PY'
import json
import pathlib
import sys

document = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
trust = document.get("trust")
if not isinstance(trust, list) or len(trust) != 1:
    raise SystemExit(f"unexpected outage decision envelope: {document!r}")
reputation = trust[0].get("reputation", {})
if reputation.get("status") != sys.argv[2]:
    raise SystemExit(
        f"reputation status={reputation.get('status')!r}, expected={sys.argv[2]!r}: {reputation!r}"
    )
PY
  done <<'CASES'
7 off 0 allow not-consulted
8 audit 0 allow unavailable
9 warn 23 confirmation-required unavailable
10 require-established 20 deny unavailable
CASES

  "$phase5_bin_dir/cpak" remove --branch main "$origin"
  "$phase5_bin_dir/cpak" system reputation-provider-set "$phase5_dir/reputation-provider.json" \
    --fingerprint "$provider_key" --yes
  import_reputation_status 7 established "$publisher_id"
  write_x509_generation 11 "$origin" "$image_digest"
  write_reputation_policy "$phase5_dir/trust-policy.json" "$publisher_id" warn
  "$phase5_bin_dir/cpak" system set-trust "$phase5_dir/trust-policy.json"
  run_install_decision 0 allow reputation-outage-recovered "$origin"

  printf 'phase5: all offline reputation policy modes and recovery passed\n'
}

run_install_decision() {
  local expected_status="$1"
  local expected_action="$2"
  local label="$3"
  local origin="$4"
  local output="$phase5_dir/install-$label.json"
  local status

  set +e
  timeout 20 "$phase5_bin_dir/cpak" install --branch main --yes --non-interactive --json "$origin" \
    </dev/null >"$output" 2>"$phase5_dir/install-$label.err"
  status=$?
  set -e
  assert_trust_envelope "$expected_status" "$expected_action" non-interactive install "$output" "$status"
}

run_update_decision() {
  local expected_status="$1"
  local expected_action="$2"
  local label="$3"
  local origin="$4"
  local output="$phase5_dir/update-$label.json"
  local status

  set +e
  timeout 20 "$phase5_bin_dir/cpak" update --non-interactive --json "$origin" \
    </dev/null >"$output" 2>"$phase5_dir/update-$label.err"
  status=$?
  set -e
  assert_trust_envelope "$expected_status" "$expected_action" non-interactive update "$output" "$status"
}

run_signed_to_unsigned_lifecycle() {
  local origin="$1"
  local image_digest="$2"
  local marker="$phase5_dir/serve-unsigned"

  write_x509_generation 12 "$origin" "$image_digest"
  : >"$marker"
  chmod 0600 "$marker"
  run_update_decision 20 deny signed-to-unsigned "$origin"
  python3 - "$phase5_dir/update-signed-to-unsigned.json" <<'PY'
import json
import pathlib
import sys

document = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
trust = document.get("trust")
if not isinstance(trust, list) or len(trust) != 1:
    raise SystemExit(f"unexpected signed-to-unsigned envelope: {document!r}")
result = trust[0]
if result.get("verification", {}).get("status") != "unsigned":
    raise SystemExit(f"signed-to-unsigned update was not visible as unsigned: {result!r}")
if result.get("publisher", {}).get("status") != "absent":
    raise SystemExit(f"signed-to-unsigned update retained a publisher: {result!r}")
if result.get("policy", {}).get("action") != "deny":
    raise SystemExit(f"signature policy did not deny the unsigned update: {result!r}")
PY

  rm -f -- "$marker"
  run_update_decision 0 allow signed-to-unsigned-recovered "$origin"
  python3 - "$phase5_dir/update-signed-to-unsigned-recovered.json" <<'PY'
import json
import pathlib
import sys

document = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
result = document.get("trust", [{}])[0]
if result.get("verification", {}).get("status") != "verified" or result.get("publisher", {}).get("status") != "verified":
    raise SystemExit(f"restored signed update did not recover cleanly: {result!r}")
PY

  printf 'phase5: signed-to-unsigned policy refusal and signed recovery passed\n'
}

run_replayed_generation_lifecycle() {
  local origin="$1"
  local image_digest="$2"

  printf '11\n' >"$phase5_dir/generation"
  run_update_decision 20 deny replayed-generation "$origin"
  python3 - "$phase5_dir/update-replayed-generation.json" <<'PY'
import json
import pathlib
import sys

document = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
result = document.get("trust", [{}])[0]
final = result.get("final", {})
if result.get("subject", {}).get("generation") != 11:
    raise SystemExit(f"the replayed publisher generation was not reported: {result!r}")
if final.get("reason_code") != "publisher-generation-downgrade":
    raise SystemExit(f"the replay was not reported as a publisher downgrade: {final!r}")
PY

  write_x509_generation 13 "$origin" "$image_digest"
  run_update_decision 0 allow replayed-generation-recovered "$origin"

  printf 'phase5: replayed publisher generation refusal and recovery passed\n'
}

run_publisher_key_rotation_lifecycle() {
  local origin="$1"
  local original_publisher_id="$2"
  local image_digest="$3"
  local decision="$phase5_dir/decision-publisher-rotated.json"
  local rotated_publisher_id status

  write_x509_generation 14 "$origin" "$image_digest" publisher-rotated
  set +e
  "$phase5_bin_dir/cpak" verify-signature "$phase5_dir/state-14.cms" \
    --state "$phase5_dir/state-14" --evidence-kind x509-cms --json >"$decision"
  status=$?
  set -e
  assert_decision 0 allow "$decision" "$status"
  rotated_publisher_id="$(python3 - "$decision" <<'PY'
import json
import pathlib
import sys

document = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
publisher = document.get("publisher", {})
if publisher.get("status") != "verified" or not publisher.get("id"):
    raise SystemExit(f"rotated publisher was not verified: {publisher!r}")
print(publisher["id"])
PY
)"
  [[ "$rotated_publisher_id" != "$original_publisher_id" ]] || \
    fail "publisher key rotation retained the original normalized identity"

  run_update_decision 20 deny publisher-key-unapproved "$origin"
  python3 - "$phase5_dir/update-publisher-key-unapproved.json" "$rotated_publisher_id" <<'PY'
import json
import pathlib
import sys

document = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
result = document.get("trust", [{}])[0]
if result.get("publisher", {}).get("id") != sys.argv[2]:
    raise SystemExit(f"the changed publisher identity was not visible: {result!r}")
if result.get("policy", {}).get("action") != "deny":
    raise SystemExit(f"the unapproved publisher was not denied: {result!r}")
if result.get("reputation", {}).get("status") != "not-consulted":
    raise SystemExit(f"reputation ran before publisher policy: {result!r}")
PY

  write_reputation_policy "$phase5_dir/trust-policy-rotated.json" \
    "$rotated_publisher_id" require-established
  "$phase5_bin_dir/cpak" system set-trust "$phase5_dir/trust-policy-rotated.json"
  run_update_decision 20 deny publisher-key-without-reputation "$origin"
  python3 - "$phase5_dir/update-publisher-key-without-reputation.json" "$rotated_publisher_id" <<'PY'
import json
import pathlib
import sys

document = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
result = document.get("trust", [{}])[0]
reputation = result.get("reputation", {})
if result.get("publisher", {}).get("id") != sys.argv[2] or reputation.get("status") != "unknown":
    raise SystemExit(f"the new publisher borrowed another identity's reputation: {result!r}")
if result.get("policy", {}).get("action") != "deny":
    raise SystemExit(f"the new publisher without established reputation was not denied: {result!r}")
PY

  import_reputation_status 8 established "$rotated_publisher_id"
  run_update_decision 0 allow publisher-key-established "$origin"
  python3 - "$phase5_dir/update-publisher-key-established.json" "$rotated_publisher_id" <<'PY'
import json
import pathlib
import sys

document = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
result = document.get("trust", [{}])[0]
reputation = result.get("reputation", {})
if result.get("publisher", {}).get("id") != sys.argv[2]:
    raise SystemExit(f"the accepted update recorded the wrong publisher: {result!r}")
if reputation.get("status") != "established":
    raise SystemExit(f"the accepted update did not use the new publisher's reputation: {result!r}")
PY

  printf 'phase5: publisher key rotation isolation, refusal, and recovery passed\n'
}

run_stale_evidence_lifecycle() {
  local origin="$1"
  local image_digest="$2"
  local updated_image_digest="$3"
  local marker="$phase5_dir/serve-updated-image"
  local status

  write_x509_generation 15 "$origin" "$image_digest" publisher-rotated
  : >"$marker"
  chmod 0600 "$marker"

  run_update_decision 21 invalid stale-evidence "$origin"
  python3 - "$phase5_dir/update-stale-evidence.json" <<'PY'
import json
import pathlib
import sys

document = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
result = document.get("trust", [{}])[0]
if result.get("verification", {}).get("status") != "invalid":
    raise SystemExit(f"stale publisher evidence was not invalid: {result!r}")
if result.get("final", {}).get("action") != "invalid":
    raise SystemExit(f"stale publisher evidence did not fail before policy: {result!r}")
PY

  set +e
  timeout 20 "$phase5_bin_dir/cpak" run --branch main "$origin" phase5-fixture \
    </dev/null >"$phase5_dir/run-stale-evidence.out" 2>"$phase5_dir/run-stale-evidence.err"
  status=$?
  set -e
  [[ "$status" -ne 0 && "$status" -ne 124 ]] || \
    fail "the package changed under stale publisher evidence was allowed to launch"
  if ! grep -F 'does not match the integrity anchor it was enrolled with' \
    "$phase5_dir/run-stale-evidence.err" >/dev/null; then
    tail -n 80 "$phase5_dir/run-stale-evidence.err" >&2 || true
    fail "the stale-evidence launch refusal did not report its anchor mismatch"
  fi

  write_x509_generation 15 "$origin" "$updated_image_digest" publisher-rotated
  run_update_decision 0 allow stale-evidence-recovered "$origin"
  set +e
  timeout 30 "$phase5_bin_dir/cpak" run --branch main "$origin" phase5-fixture \
    </dev/null >"$phase5_dir/run-stale-evidence-recovered.out" \
    2>"$phase5_dir/run-stale-evidence-recovered.err"
  status=$?
  set -e
  if [[ "$status" -ne 0 ]]; then
    tail -n 80 "$phase5_dir/run-stale-evidence-recovered.err" >&2 || true
    fail "the freshly signed package launch exited $status"
  fi
  grep -Fx 'phase5 fixture executed' "$phase5_dir/run-stale-evidence-recovered.out" >/dev/null || \
    fail "the freshly signed package did not execute its stored payload"
  "$phase5_bin_dir/cpak" stop --branch main "$origin"
  rm -f -- "$marker"

  printf 'phase5: changed package stale-evidence refusal and signed recovery passed\n'
}

run_process_negative_lifecycle() {
  local origin="$1"
  local publisher_id="$2"
  local image_digest="$3"

  "$phase5_bin_dir/cpak" remove --branch main "$origin"
  write_x509_generation 3 "$origin" "$image_digest"
  cp "$phase5_dir/state-3.cms" "$phase5_dir/state-3.valid.cms"
  python3 - "$phase5_dir/state-3.cms" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
payload = bytearray(path.read_bytes())
if len(payload) < 32:
    raise SystemExit("the CMS fixture is unexpectedly short")
payload[len(payload) // 2] ^= 1
path.write_bytes(payload)
PY
  run_install_decision 21 invalid invalid-evidence "$origin"

  mv "$phase5_dir/state-3.valid.cms" "$phase5_dir/state-3.cms"
  import_reputation_status 4 established "$publisher_id"
  run_install_decision 0 allow invalid-evidence-recovered "$origin"

  "$phase5_bin_dir/cpak" remove --branch main "$origin"
  write_x509_generation 4 "$origin" "$image_digest"
  local crl_directory="/etc/cpak/trust/revocation/code-signing.d"
  local revoked_crl="$crl_directory/phase5-publisher-revoked.pem"
  mkdir -p "$crl_directory"
  chmod 0755 /etc/cpak/trust/revocation "$crl_directory"
  cp "$phase5_dir/pki/publisher-revoked.crl.pem" "$revoked_crl"
  chmod 0644 "$revoked_crl"

  local status
  set +e
  "$phase5_bin_dir/cpak" verify-signature "$phase5_dir/state-4.cms" \
    --state "$phase5_dir/state-4" --evidence-kind x509-cms --json \
    >"$phase5_dir/verify-revoked.json" 2>"$phase5_dir/verify-revoked.err"
  status=$?
  set -e
  assert_decision 20 deny "$phase5_dir/verify-revoked.json" "$status"
  python3 - "$phase5_dir/verify-revoked.json" <<'PY'
import json
import pathlib
import sys

document = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
if document.get("trust", {}).get("revocation") != "revoked":
    raise SystemExit(f"the negative CRL did not produce revoked: {document!r}")
if document.get("trust", {}).get("reason_code") != "certificate-revoked":
    raise SystemExit(f"the revoked decision lost its reason: {document!r}")
PY
  run_install_decision 20 deny revoked-certificate "$origin"

  rm -f -- "$revoked_crl"
  run_install_decision 0 allow revoked-certificate-recovered "$origin"

  "$phase5_bin_dir/cpak" remove --branch main "$origin"
  write_x509_generation 5 "$origin" "$image_digest"
  python3 - "$phase5_dir/trust-policy-denied.json" "$publisher_id" "$origin" <<'PY'
import json
import pathlib
import sys

policy = {
    "abi": 2,
    "require_publisher": True,
    "require_approval": False,
    "approved_publisher_ids": [sys.argv[2]],
    "revoked": [{"origin": sys.argv[3], "generation": 5, "reason": "phase5-admin-denial"}],
    "x509": {"revocation": "allow-unknown"},
    "reputation": {"mode": "warn", "provider_id": "cpak-phase5"},
}
pathlib.Path(sys.argv[1]).write_text(json.dumps(policy) + "\n", encoding="utf-8")
PY
  "$phase5_bin_dir/cpak" system set-trust "$phase5_dir/trust-policy-denied.json"
  run_install_decision 20 deny administrator-denied "$origin"

  "$phase5_bin_dir/cpak" system set-trust "$phase5_dir/trust-policy.json"
  run_install_decision 0 allow administrator-denial-recovered "$origin"

  "$phase5_bin_dir/cpak" remove --branch main "$origin"
  write_x509_generation 6 "$origin" "$image_digest"
  import_reputation_status 5 blocked "$publisher_id"
  run_install_decision 20 deny blocked-reputation "$origin"
  python3 - "$phase5_dir/install-blocked-reputation.json" <<'PY'
import json
import pathlib
import sys

document = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
trust = document.get("trust", [{}])[0]
if trust.get("reputation", {}).get("status") != "blocked" or trust.get("policy", {}).get("action") != "deny":
    raise SystemExit(f"blocked reputation did not remain a denial: {trust!r}")
PY

  import_reputation_status 6 established "$publisher_id"
  run_install_decision 0 allow blocked-reputation-recovered "$origin"

  printf 'phase5: invalid, revoked, administrator-denied, and blocked --yes lifecycle passed\n'
}

run_process_lifecycle() {
  local publisher_id="$1"

  cp /etc/hosts "$phase5_dir/hosts"
  printf '127.0.0.1 phase5.invalid\n' >>"$phase5_dir/hosts"
  mount --bind "$phase5_dir/hosts" /etc/hosts

  "$phase5_bin_dir/cpak-phase5-fixture" --directory "$phase5_dir" \
    --payload "$phase5_bin_dir/phase5-payload" \
    >"$phase5_dir/fixture-server.log" 2>&1 &
  fixture_pid=$!
  for _ in {1..100}; do
    [[ -s "$phase5_dir/fixture.json" ]] && break
    kill -0 "$fixture_pid" 2>/dev/null || fail "the Phase 5 fixture server stopped"
    sleep 0.1
  done
  [[ -s "$phase5_dir/fixture.json" ]] || fail "the Phase 5 fixture server did not become ready"

  local origin image image_digest updated_image_digest tls_root
  origin="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["origin"])' "$phase5_dir/fixture.json")"
  image="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["image"])' "$phase5_dir/fixture.json")"
  image_digest="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["image_digest"])' "$phase5_dir/fixture.json")"
  updated_image_digest="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["updated_image_digest"])' "$phase5_dir/fixture.json")"
  tls_root="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["tls_root"])' "$phase5_dir/fixture.json")"
  export SSL_CERT_FILE="$tls_root"
  export NO_PROXY="phase5.invalid,127.0.0.1,localhost"
  export no_proxy="$NO_PROXY"

  python3 - "$phase5_dir/cpak.json" "$image" <<'PY'
import json
import pathlib
import sys

manifest = {
    "manifest_version": "2.0",
    "name": "Phase 5 binary fixture",
    "description": "Headless application-trust lifecycle fixture",
    "image": sys.argv[2],
    "binaries": ["/usr/bin/phase5-fixture"],
    "idle_time": 0,
    "override": {},
}
pathlib.Path(sys.argv[1]).write_text(json.dumps(manifest) + "\n", encoding="utf-8")
PY
  "$phase5_bin_dir/cpak-sign" state \
    --manifest "$phase5_dir/cpak.json" \
    --origin "$origin" \
    --image-digest "$image_digest" \
    --generation 1 \
    --output "$phase5_dir/state-1"
  "$phase5_bin_dir/cpak-sign" x509-sign \
    --state "$phase5_dir/state-1" \
    --certificate "$phase5_dir/pki/publisher.pem" \
    --chain "$phase5_dir/pki/publisher-chain.pem" \
    --key "$phase5_dir/pki/publisher-key.pem" \
    --key-passphrase-file "$phase5_dir/passphrase" \
    --output "$phase5_dir/state-1.cms"
  printf '1\n' >"$phase5_dir/generation"

  import_reputation_status 2 caution "$publisher_id"
  python3 - "$phase5_dir/trust-policy.json" "$publisher_id" <<'PY'
import json
import pathlib
import sys

policy = {
    "abi": 2,
    "require_publisher": True,
    "require_approval": False,
    "approved_publisher_ids": [sys.argv[2]],
    "x509": {"revocation": "allow-unknown"},
    "reputation": {"mode": "warn", "provider_id": "cpak-phase5"},
}
pathlib.Path(sys.argv[1]).write_text(json.dumps(policy) + "\n", encoding="utf-8")
PY
  "$phase5_bin_dir/cpak" system set-trust "$phase5_dir/trust-policy.json"

  local status
  set +e
  timeout 20 "$phase5_bin_dir/cpak" install --branch main --yes --non-interactive --json "$origin" \
    </dev/null >"$phase5_dir/install-non-interactive.json" 2>"$phase5_dir/install-non-interactive.err"
  status=$?
  set -e
  assert_trust_envelope 23 confirmation-required non-interactive install \
    "$phase5_dir/install-non-interactive.json" "$status"

  set +e
  timeout 20 "$phase5_bin_dir/cpak" install --branch main --yes --non-interactive "$origin" \
    </dev/null >"$phase5_dir/install-non-interactive-human.log" 2>&1
  status=$?
  set -e
  assert_human_trust_projection "$phase5_dir/install-non-interactive.json" \
    "$phase5_dir/install-non-interactive-human.log" "$status"

  if [[ "$graphical_runtime" == "1" ]]; then
    run_graphical_enrolment "$origin"
    "$phase5_bin_dir/cpak" system explain "$origin" --json >"$phase5_dir/explain-graphical.json"
    python3 - "$phase5_dir/explain-graphical.json" <<'PY'
import json
import pathlib
import sys

document = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
trust = document.get("trust", {})
# The non-interactive install above was refused (exit 23), so an enrolment here
# can only have come from run_graphical_enrolment. explain observes the recorded
# decision non-interactively, so trust.context reflects this reader, not the
# graphical install that recorded the accepted warn decision below.
if not document.get("launch", {}).get("enrolled"):
    raise SystemExit("the graphical confirmation did not enrol the installation")
if trust.get("decision_source") != "recorded" or trust.get("final", {}).get("action") != "warn":
    raise SystemExit(f"the graphical install did not record a warn decision: {trust!r}")
if trust.get("policy", {}).get("confirmation") != "accepted":
    raise SystemExit(f"the graphical confirmation was not recorded as accepted: {trust!r}")
PY
    "$phase5_bin_dir/cpak" remove --branch main "$origin"

    set +e
    timeout 20 "$phase5_bin_dir/cpak" install --branch main --yes --non-interactive --json "$origin" \
      </dev/null >"$phase5_dir/install-non-interactive.json" 2>"$phase5_dir/install-non-interactive.err"
    status=$?
    set -e
    assert_trust_envelope 23 confirmation-required non-interactive install \
      "$phase5_dir/install-non-interactive.json" "$status"
  fi

  set +e
  printf 'y\n' | script -qfec \
    "$phase5_bin_dir/cpak install --branch main --yes $origin" /dev/null \
    >"$phase5_dir/install-terminal.log" 2>&1
  status=$?
  set -e
  [[ "$status" -eq 0 ]] || fail "interactive terminal enrolment exited $status"
  grep -F 'confirmation accepted' "$phase5_dir/install-terminal.log" >/dev/null || \
    fail "interactive terminal result did not record accepted confirmation"

  "$phase5_bin_dir/cpak" system explain "$origin" --json >"$phase5_dir/explain-recorded.json"
  python3 - "$phase5_dir/explain-recorded.json" <<'PY'
import json
import pathlib
import sys

document = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
trust = document.get("trust", {})
if document.get("schema_version") != 1 or not document.get("launch", {}).get("enrolled"):
    raise SystemExit("the accepted install is not enrolled in explain output")
if trust.get("decision_source") != "recorded" or trust.get("final", {}).get("action") != "warn":
    raise SystemExit(f"unexpected recorded decision: {trust!r}")
if trust.get("policy", {}).get("confirmation") != "accepted":
    raise SystemExit(f"accepted confirmation was not recorded: {trust!r}")
PY

  "$phase5_bin_dir/cpak-sign" state \
    --manifest "$phase5_dir/cpak.json" \
    --origin "$origin" \
    --image-digest "$image_digest" \
    --generation 2 \
    --output "$phase5_dir/state-2"
  "$phase5_bin_dir/cpak-sign" x509-sign \
    --state "$phase5_dir/state-2" \
    --certificate "$phase5_dir/pki/publisher.pem" \
    --chain "$phase5_dir/pki/publisher-chain.pem" \
    --key "$phase5_dir/pki/publisher-key.pem" \
    --key-passphrase-file "$phase5_dir/passphrase" \
    --output "$phase5_dir/state-2.cms"
  printf '2\n' >"$phase5_dir/generation"
  import_reputation_status 3 established "$publisher_id"

  set +e
  "$phase5_bin_dir/cpak" update --non-interactive --json "$origin" \
    >"$phase5_dir/update-non-interactive.json" 2>"$phase5_dir/update-non-interactive.err"
  status=$?
  set -e
  assert_trust_envelope 0 allow non-interactive update \
    "$phase5_dir/update-non-interactive.json" "$status"

  run_service_lifecycle "$origin"
  run_process_negative_lifecycle "$origin" "$publisher_id" "$image_digest"

  "$phase5_bin_dir/cpak" system reputation-provider-clear \
    --fingerprint "$provider_key" --yes
  run_reputation_outage_matrix "$origin" "$publisher_id" "$image_digest"
  run_signed_to_unsigned_lifecycle "$origin" "$image_digest"
  run_replayed_generation_lifecycle "$origin" "$image_digest"
  run_publisher_key_rotation_lifecycle "$origin" "$publisher_id" "$image_digest"
  run_stale_evidence_lifecycle "$origin" "$image_digest" "$updated_image_digest"
  "$phase5_bin_dir/cpak" system reputation-provider-clear \
    --fingerprint "$provider_key" --yes
  kill "$fixture_pid"
  wait "$fixture_pid" 2>/dev/null || true
  fixture_pid=""

  set +e
  timeout 30 "$phase5_bin_dir/cpak" run --branch main "$origin" phase5-fixture \
    </dev/null >"$phase5_dir/run-offline.out" 2>"$phase5_dir/run-offline.err"
  status=$?
  set -e
  if [[ "$status" -ne 0 ]]; then
    python3 - "$phase5_dir/run-offline.err" <<'PY'
import pathlib
import sys
print(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace")[-4000:], file=sys.stderr)
PY
    fail "offline binary execution exited $status"
  fi
  grep -Fx 'phase5 fixture executed' "$phase5_dir/run-offline.out" >/dev/null || \
    fail "offline binary execution did not return the fixture output"
  "$phase5_bin_dir/cpak" stop --branch main "$origin"

  "$phase5_bin_dir/cpak" system explain "$origin" --json >"$phase5_dir/explain-offline.json"
  "$phase5_bin_dir/cpak" audit --json >"$phase5_dir/audit-offline.json"
  python3 - "$phase5_dir/explain-offline.json" "$phase5_dir/audit-offline.json" <<'PY'
import json
import pathlib
import sys

explain = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
audit = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
if explain.get("trust", {}).get("reputation", {}).get("status") != "established":
    raise SystemExit("offline explain did not retain the recorded established reputation")
trust = audit.get("trust")
if not isinstance(trust, list) or len(trust) != 1 or trust[0].get("decision_source") != "recorded":
    raise SystemExit("offline audit did not emit one recorded trust result")
if trust[0].get("final", {}).get("exit_code") != 0:
    raise SystemExit("offline audit and recorded final exit disagree")
PY

  printf 'phase5: real CLI install, retry, update, explain, audit, and offline lifecycle passed\n'
}

run_sigstore_lifecycle() {
  local origin="$1"

  [[ "$origin" =~ ^github\.com/[a-z0-9._-]+/[a-z0-9._-]+$ ]] || \
    fail "the Sigstore fixture origin must be one canonical GitHub repository"

  printf '127.0.0.1 %s\n' "${origin%%/*}" >>"$phase5_dir/hosts"
  rm -f "$phase5_dir/fixture.json"
  "$phase5_bin_dir/cpak-phase5-fixture" --directory "$phase5_dir" \
    --payload "$phase5_bin_dir/phase5-payload" \
    --origin "$origin" --evidence-kind sigstore \
    >"$phase5_dir/fixture-sigstore.log" 2>&1 &
  fixture_pid=$!
  for _ in {1..100}; do
    [[ -s "$phase5_dir/fixture.json" ]] && break
    kill -0 "$fixture_pid" 2>/dev/null || fail "the Sigstore fixture server stopped"
    sleep 0.1
  done
  [[ -s "$phase5_dir/fixture.json" ]] || fail "the Sigstore fixture server did not become ready"

  local image image_digest tls_root
  image="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["image"])' "$phase5_dir/fixture.json")"
  image_digest="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["image_digest"])' "$phase5_dir/fixture.json")"
  tls_root="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["tls_root"])' "$phase5_dir/fixture.json")"
  export SSL_CERT_FILE="$tls_root"
  export NO_PROXY="${origin%%/*},phase5.invalid,127.0.0.1,localhost"
  export no_proxy="$NO_PROXY"

  python3 - "$phase5_dir/cpak.json" "$image" <<'PY'
import json
import pathlib
import sys

manifest = {
    "manifest_version": "2.0",
    "name": "Phase 5 Sigstore fixture",
    "description": "Real keyless Sigstore install and update fixture",
    "image": sys.argv[2],
    "binaries": ["/usr/bin/phase5-fixture"],
    "idle_time": 0,
    "override": {},
}
pathlib.Path(sys.argv[1]).write_text(json.dumps(manifest) + "\n", encoding="utf-8")
PY

  local generation
  for generation in 1 2; do
    "$phase5_bin_dir/cpak-sign" state \
      --manifest "$phase5_dir/cpak.json" \
      --origin "$origin" \
      --image-digest "$image_digest" \
      --generation "$generation" \
      --output "$phase5_dir/state-$generation"
    env -u SSL_CERT_FILE \
      ACTIONS_ID_TOKEN_REQUEST_TOKEN="$sigstore_oidc_token" \
      ACTIONS_ID_TOKEN_REQUEST_URL="$sigstore_oidc_url" \
      cosign sign-blob --yes \
      --bundle "$phase5_dir/state-$generation.sigstore.json" \
      "$phase5_dir/state-$generation"
  done
  sigstore_oidc_token=""
  sigstore_oidc_url=""
  printf '1\n' >"$phase5_dir/generation"

  local decision="$phase5_dir/decision-sigstore.json"
  local status
  set +e
  "$phase5_bin_dir/cpak" verify-signature "$phase5_dir/state-1.sigstore.json" \
    --state "$phase5_dir/state-1" --evidence-kind sigstore --json >"$decision"
  status=$?
  set -e
  assert_decision 0 allow "$decision" "$status"

  local publisher_id
  publisher_id="$(python3 - "$decision" <<'PY'
import json
import pathlib
import sys

document = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
if document.get("verification", {}).get("evidence_kind") != "sigstore-bundle-v1":
    raise SystemExit(f"unexpected evidence kind: {document!r}")
if document.get("publisher", {}).get("origin_authorization") != "authorized":
    raise SystemExit(f"Sigstore identity does not authorize the fixture origin: {document!r}")
print(document["publisher"]["id"])
PY
)"

  "$phase5_bin_dir/cpak" system reputation-provider-set "$phase5_dir/reputation-provider.json" \
    --fingerprint "$provider_key" --yes
  import_reputation_status 9 established "$publisher_id"
  python3 - "$phase5_dir/trust-policy-sigstore.json" "$publisher_id" <<'PY'
import json
import pathlib
import sys

policy = {
    "abi": 2,
    "require_publisher": True,
    "require_approval": False,
    "approved_publisher_ids": [sys.argv[2]],
    "x509": {"revocation": "allow-unknown"},
    "reputation": {"mode": "require-established", "provider_id": "cpak-phase5"},
}
pathlib.Path(sys.argv[1]).write_text(json.dumps(policy) + "\n", encoding="utf-8")
PY
  "$phase5_bin_dir/cpak" system set-trust "$phase5_dir/trust-policy-sigstore.json"

  set +e
  "$phase5_bin_dir/cpak" install --branch main --yes --non-interactive --json "$origin" \
    >"$phase5_dir/install-sigstore.json" 2>"$phase5_dir/install-sigstore.err"
  status=$?
  set -e
  assert_trust_envelope 0 allow non-interactive install "$phase5_dir/install-sigstore.json" "$status"
  assert_sigstore_envelope "$phase5_dir/install-sigstore.json" 1

  printf '2\n' >"$phase5_dir/generation"
  set +e
  "$phase5_bin_dir/cpak" update --non-interactive --json "$origin" \
    >"$phase5_dir/update-sigstore.json" 2>"$phase5_dir/update-sigstore.err"
  status=$?
  set -e
  assert_trust_envelope 0 allow non-interactive update "$phase5_dir/update-sigstore.json" "$status"
  assert_sigstore_envelope "$phase5_dir/update-sigstore.json" 2

  "$phase5_bin_dir/cpak" remove --branch main "$origin"
  "$phase5_bin_dir/cpak" system reputation-provider-clear --fingerprint "$provider_key" --yes
  kill "$fixture_pid"
  wait "$fixture_pid" 2>/dev/null || true
  fixture_pid=""
  printf 'phase5: real keyless Sigstore OCI install and update passed\n'
}

assert_sigstore_envelope() {
  local output="$1"
  local expected_generation="$2"
  python3 - "$output" "$expected_generation" <<'PY'
import json
import pathlib
import sys

document = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
trust = document.get("trust")
if not isinstance(trust, list) or len(trust) != 1:
    raise SystemExit(f"unexpected trust envelope: {trust!r}")
result = trust[0]
expected_generation = int(sys.argv[2])
if result.get("subject", {}).get("generation") != expected_generation:
    raise SystemExit(f"unexpected publisher generation: {result.get('subject')!r}")
if result.get("verification", {}) != {
    "status": "verified",
    "evidence_kind": "sigstore-bundle-v1",
    "reason_code": "evidence-verified",
}:
    raise SystemExit(f"unexpected Sigstore verification: {result.get('verification')!r}")
publisher = result.get("publisher", {})
if publisher.get("status") != "verified" or publisher.get("origin_authorization") != "authorized":
    raise SystemExit(f"unexpected Sigstore publisher: {publisher!r}")
root = result.get("trust", {})
if root.get("chain") != "trusted-public" or root.get("root_source") != "bundled-sigstore" or root.get("signing_time") != "timestamped":
    raise SystemExit(f"unexpected Sigstore trust root: {root!r}")
reputation = result.get("reputation", {})
if reputation.get("provider_id") != "cpak-phase5" or reputation.get("status") != "established" or reputation.get("freshness") != "fresh":
    raise SystemExit(f"unexpected publisher reputation: {reputation!r}")
PY
}

inside_namespace() {
  phase5_dir="$2"
  local phase5_bin_source="$3"
  phase5_bin_dir="/opt/cpak-phase5"
  cleanup_uid="${4:-}"
  cleanup_gid="${5:-}"
  local phase5_data_root="${6:-$phase5_dir/home/.local/share}"
  frontend_user="${7:-}"
  graphical_runtime="${8:-}"
  sigstore_origin="${9:-}"
  local sigstore_oidc_token_path="${10:-}"
  local sigstore_oidc_url_path="${11:-}"
  unset SUDO_UID SUDO_GID SUDO_USER
  fixture_pid=""
  xvfb_pid=""
  wm_pid=""
  service_pid=""
  service_origin=""
  cleanup_namespace() {
    if [[ -n "$fixture_pid" ]]; then
      kill "$fixture_pid" 2>/dev/null || true
      wait "$fixture_pid" 2>/dev/null || true
    fi
    if [[ -n "$wm_pid" ]]; then
      kill "$wm_pid" 2>/dev/null || true
      wait "$wm_pid" 2>/dev/null || true
    fi
    if [[ -n "$xvfb_pid" ]]; then
      kill "$xvfb_pid" 2>/dev/null || true
      wait "$xvfb_pid" 2>/dev/null || true
    fi
    if [[ -n "$service_origin" ]]; then
      timeout 20 "$phase5_bin_dir/cpak" stop --branch main "$service_origin" \
        >/dev/null 2>&1 || true
    fi
    if [[ -n "$service_pid" ]]; then
      kill "$service_pid" 2>/dev/null || true
      wait "$service_pid" 2>/dev/null || true
    fi
    if [[ -n "$cleanup_uid" && -n "$cleanup_gid" ]]; then
      chown -R "$cleanup_uid:$cleanup_gid" "$phase5_dir"
    fi
  }
  trap cleanup_namespace EXIT
  export HOME="$phase5_dir/home"
  export XDG_CONFIG_HOME="$HOME/.config"
  export XDG_DATA_HOME="$phase5_data_root/xdg"
  export XDG_STATE_HOME="$HOME/.local/state"
  export CPAK_INSTALLATION_PATH="$phase5_data_root/cpak"
  unset DISPLAY WAYLAND_DISPLAY DBUS_SESSION_BUS_ADDRESS

  mkdir -p "$HOME" "$XDG_CONFIG_HOME" "$XDG_DATA_HOME" "$XDG_STATE_HOME"
  mount --make-rprivate /
  mount -t tmpfs -o mode=0755,nosuid,nodev tmpfs /var/lib
  mkdir -p /var/lib/cpak
  mkdir -p /etc/cpak/trust
  mount -t tmpfs -o mode=0755,nosuid,nodev,noexec tmpfs /etc/cpak/trust
  [[ -d "$phase5_bin_source" ]] || fail "executable staging directory is unavailable"
  mkdir -p "$phase5_bin_dir"
  mount -t tmpfs -o mode=0755,nosuid,nodev,exec tmpfs "$phase5_bin_dir"
  cp -a "$phase5_bin_source/." "$phase5_bin_dir/"
  chown -R root:root "$phase5_bin_dir"

  if [[ -n "$frontend_user" ]]; then
    [[ "$frontend_user" =~ ^[a-z_][a-z0-9_-]*$ ]] || fail "unsafe privilege frontend user"
    for required in runuser visudo sudo doas; do
      require_command "$required"
    done
    for frontend in sudo doas; do
      local frontend_binary
      frontend_binary="$(command -v "$frontend")"
      mkdir -p "$phase5_bin_dir/frontend-$frontend"
      ln -s "$frontend_binary" "$phase5_bin_dir/frontend-$frontend/$frontend"
    done
  fi
  if [[ "$graphical_runtime" == "1" ]]; then
    require_command Xvfb
    require_command xwininfo
    require_command xprop
    require_command openbox
  elif [[ -n "$graphical_runtime" ]]; then
    fail "CPAK_PHASE5_GRAPHICAL must be empty or 1"
  fi
  if [[ -n "$sigstore_origin" ]]; then
    require_command cosign
    [[ -f "$sigstore_oidc_token_path" && -f "$sigstore_oidc_url_path" ]] || \
      fail "the Sigstore lifecycle requires staged GitHub Actions OIDC material"
    IFS= read -r sigstore_oidc_token <"$sigstore_oidc_token_path"
    IFS= read -r sigstore_oidc_url <"$sigstore_oidc_url_path"
    rm -f -- "$sigstore_oidc_token_path" "$sigstore_oidc_url_path"
    [[ -n "$sigstore_oidc_token" && -n "$sigstore_oidc_url" ]] || \
      fail "the staged GitHub Actions OIDC material is empty"
  fi

  local root_fingerprint
  root_fingerprint="$(python3 - "$phase5_dir/pki/manifest.json" <<'PY'
import json
import pathlib
import sys
print(json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))["sha256_fingerprints"]["root.pem"])
PY
)"

  verify_x509 21 invalid
  if [[ -n "$frontend_user" ]]; then
    exercise_root_frontend sudo "$root_fingerprint"
    exercise_root_frontend doas "$root_fingerprint"
  fi
  "$phase5_bin_dir/cpak" system trust-root-add "$phase5_dir/pki/root.pem" \
    --purpose code-signing --fingerprint "$root_fingerprint" --yes
  verify_x509 0 allow

  local publisher_id
  publisher_id="$(python3 - "$phase5_dir/decision-0-allow.json" <<'PY'
import json
import pathlib
import sys
print(json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))["publisher"]["id"])
PY
)"

  python3 - "$phase5_dir/reputation-payload.json" "$publisher_id" <<'PY'
import datetime
import json
import pathlib
import sys

now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
payload = {
    "sequence": 1,
    "issued_at": (now - datetime.timedelta(minutes=1)).isoformat().replace("+00:00", "Z"),
    "expires_at": (now + datetime.timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
    "entries": [{
        "publisher_id": sys.argv[2],
        "status": "established",
        "reason_code": "phase5-harness",
    }],
}
pathlib.Path(sys.argv[1]).write_text(json.dumps(payload, separators=(",", ":")) + "\n", encoding="utf-8")
PY
  "$phase5_bin_dir/cpak-sign" reputation-sign \
    --authority "$phase5_dir/reputation-provider.json" \
    --key "$phase5_dir/reputation-provider-key.pem" \
    --key-passphrase-file "$phase5_dir/passphrase" \
    --payload "$phase5_dir/reputation-payload.json" \
    --output "$phase5_dir/reputation-snapshot.json"

  local provider_key snapshot_fingerprint
  provider_key="$(python3 - "$phase5_dir/reputation-provider.json" <<'PY'
import json
import pathlib
import sys
print(json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))["key_id"])
PY
)"
  snapshot_fingerprint="$(sha256sum "$phase5_dir/reputation-snapshot.json" | awk '{print $1}')"

  if [[ -n "$frontend_user" ]]; then
    exercise_reputation_frontend sudo "$publisher_id" "$provider_key" "$snapshot_fingerprint"
    exercise_reputation_frontend doas "$publisher_id" "$provider_key" "$snapshot_fingerprint"
  fi

  "$phase5_bin_dir/cpak" system reputation-provider-set "$phase5_dir/reputation-provider.json" \
    --fingerprint "$provider_key" --yes
  "$phase5_bin_dir/cpak" system reputation-import "$phase5_dir/reputation-snapshot.json" \
    --fingerprint "$snapshot_fingerprint" --yes
  "$phase5_bin_dir/cpak" system reputation-check "$publisher_id" | grep -F 'established' >/dev/null
  if [[ -n "$cleanup_uid" && -n "$cleanup_gid" ]]; then
    run_process_lifecycle "$publisher_id"
    if [[ -n "$sigstore_origin" ]]; then
      run_sigstore_lifecycle "$sigstore_origin"
    fi
  else
    "$phase5_bin_dir/cpak" system reputation-provider-clear \
      --fingerprint "$provider_key" --yes
  fi

  "$phase5_bin_dir/cpak" system trust-root-remove "$root_fingerprint" \
    --purpose code-signing --yes
  verify_x509 21 invalid

  printf 'phase5: isolated direct-root X.509 and reputation lifecycle passed\n'
}

if [[ "${1:-}" == "--inside-namespace" ]]; then
  inside_namespace "$@"
  exit 0
fi

namespace_mode="${1:-}"
if [[ -n "$namespace_mode" && "$namespace_mode" != "--sudo-namespace" && "$namespace_mode" != "--root-namespace" ]]; then
  fail "unknown argument: $namespace_mode"
fi

sigstore_origin="${CPAK_PHASE5_SIGSTORE_ORIGIN:-}"
sigstore_oidc_token=""
sigstore_oidc_url=""
[[ "$(uname -s)" == "Linux" ]] || fail "this harness must run on Linux"
for command_name in go python3 unshare mount sha256sum awk grep cp tr wc; do
  require_command "$command_name"
done
if [[ -n "$sigstore_origin" ]]; then
  oidc_token_source="${CPAK_PHASE5_OIDC_TOKEN_FILE:-}"
  oidc_url_source="${CPAK_PHASE5_OIDC_URL_FILE:-}"
  unset CPAK_PHASE5_OIDC_TOKEN_FILE CPAK_PHASE5_OIDC_URL_FILE
  [[ "$oidc_token_source" == "/cpak-phase5-oidc/token" && "$oidc_url_source" == "/cpak-phase5-oidc/url" &&
    -f "$oidc_token_source" && ! -L "$oidc_token_source" &&
    -f "$oidc_url_source" && ! -L "$oidc_url_source" ]] || \
    fail "the Sigstore lifecycle requires its bounded GitHub Actions OIDC files"
  token_size="$(wc -c <"$oidc_token_source")"
  url_size="$(wc -c <"$oidc_url_source")"
  [[ "$token_size" -ge 2 && "$token_size" -le 16385 && "$url_size" -ge 2 && "$url_size" -le 4097 ]] || \
    fail "the GitHub Actions OIDC material exceeds its bounds"
  exec 3<"$oidc_token_source"
  IFS= read -r sigstore_oidc_token <&3 || fail "the GitHub Actions OIDC request token is unreadable"
  if IFS= read -r unexpected_oidc_input <&3; then
    fail "the GitHub Actions OIDC request token must be one line"
  fi
  exec 3<&-
  exec 3<"$oidc_url_source"
  IFS= read -r sigstore_oidc_url <&3 || fail "the GitHub Actions OIDC request URL is unreadable"
  if IFS= read -r unexpected_oidc_input <&3; then
    fail "the GitHub Actions OIDC request URL must be one line"
  fi
  exec 3<&-
  rm -f -- "$oidc_token_source" "$oidc_url_source"
  sigstore_origin="$(printf '%s' "$sigstore_origin" | tr '[:upper:]' '[:lower:]')"
  [[ "$sigstore_origin" =~ ^github\.com/[a-z0-9._-]+/[a-z0-9._-]+$ ]] || \
    fail "CPAK_PHASE5_SIGSTORE_ORIGIN must be one canonical GitHub repository"
  [[ -n "$sigstore_oidc_token" && ${#sigstore_oidc_token} -le 16384 && "$sigstore_oidc_token" != *$'\n'* ]] || \
    fail "the GitHub Actions OIDC request token is missing or malformed"
  [[ "$sigstore_oidc_url" == https://* && ${#sigstore_oidc_url} -le 4096 && "$sigstore_oidc_url" != *$'\n'* ]] || \
    fail "the GitHub Actions OIDC request URL is missing or malformed"
fi

if [[ "$namespace_mode" == "--sudo-namespace" ]]; then
  require_command sudo
fi
if [[ "$namespace_mode" == "--sudo-namespace" || "$namespace_mode" == "--root-namespace" ]]; then
  require_command id
  require_command chown
  require_command script
  require_command timeout
  require_command sleep
fi

temp_root="${TMPDIR:-/tmp}"
temp_root="${temp_root%/}"
phase5_dir="$(mktemp -d "$temp_root/cpak-phase5.XXXXXXXX")"
[[ "$phase5_dir" == "$temp_root/cpak-phase5."* ]] || fail "unsafe temporary directory"
exec_root="${CPAK_PHASE5_EXEC_ROOT:-$repo_dir}"
exec_root="${exec_root%/}"
[[ "$exec_root" == /* ]] || fail "CPAK_PHASE5_EXEC_ROOT must be absolute"
phase5_bin_dir="$(mktemp -d "$exec_root/.cpak-phase5-bin.XXXXXXXX")"
[[ "$phase5_bin_dir" == "$exec_root/.cpak-phase5-bin."* ]] || fail "unsafe executable directory"
phase5_data_root="${CPAK_PHASE5_DATA_ROOT:-$phase5_dir/home/.local/share}"
[[ "$phase5_data_root" == /* ]] || fail "CPAK_PHASE5_DATA_ROOT must be absolute"
frontend_user="${CPAK_PHASE5_FRONTEND_USER:-}"
graphical_runtime="${CPAK_PHASE5_GRAPHICAL:-}"
sigstore_oidc_token_path=""
sigstore_oidc_url_path=""
if [[ -n "$sigstore_origin" ]]; then
  sigstore_oidc_token_path="$phase5_dir/github-oidc-token"
  sigstore_oidc_url_path="$phase5_dir/github-oidc-url"
  (
    umask 077
    printf '%s\n' "$sigstore_oidc_token" >"$sigstore_oidc_token_path"
    printf '%s\n' "$sigstore_oidc_url" >"$sigstore_oidc_url_path"
  )
  sigstore_oidc_token=""
  sigstore_oidc_url=""
fi
trap 'rm -rf -- "$phase5_dir" "$phase5_bin_dir"' EXIT
chmod 0700 "$phase5_dir"
chmod 0755 "$phase5_bin_dir"
mkdir -p "$phase5_data_root"

cd "$repo_dir"
go test -race ./...
go test -tags cpak_ui_builtin ./pkg/desktopui
go vet ./...
CGO_ENABLED=0 go build -tags cpak_ui_builtin -trimpath -o "$phase5_bin_dir/cpak" .
CGO_ENABLED=0 go build -trimpath -o "$phase5_bin_dir/cpak-sign" ./cmd/cpak-sign
CGO_ENABLED=0 go build -tags cpak_ui_builtin -trimpath -o "$phase5_bin_dir/cpak-installer" ./cmd/cpak-installer
CGO_ENABLED=0 go build -trimpath -o "$phase5_bin_dir/cpak-storaged" ./cmd/cpak-storaged
CGO_ENABLED=0 go build -trimpath -o "$phase5_bin_dir/cpak-phase5-fixture" ./hack/application-trust-phase5/fixture-server
CGO_ENABLED=0 go build -trimpath -o "$phase5_bin_dir/phase5-payload" ./hack/application-trust-phase5/payload
CGO_ENABLED=0 go build -trimpath -o "$phase5_bin_dir/cpak-phase5-x11-click" ./hack/application-trust-phase5/x11-click

printf '%s\n' 'phase5-disposable-material' >"$phase5_dir/passphrase"
chmod 0600 "$phase5_dir/passphrase"
go run ./hack/poc-ca \
  --output "$phase5_dir/pki" \
  --key-passphrase-file "$phase5_dir/passphrase" \
  --publisher 'cpak Phase 5 Publisher'
"$phase5_bin_dir/cpak-sign" reputation-keygen \
  --provider cpak-phase5 \
  --key-passphrase-file "$phase5_dir/passphrase" \
  --output-key "$phase5_dir/reputation-provider-key.pem" \
  --output-authority "$phase5_dir/reputation-provider.json"

python3 - "$phase5_dir/cpak.json" <<'PY'
import json
import pathlib
import sys
manifest = {
    "manifest_version": "2.0",
    "name": "Phase 5 binary fixture",
    "description": "Headless application-trust lifecycle fixture",
    "image": "example.invalid/cpak/phase5:fixture",
    "binaries": ["/usr/bin/phase5-fixture"],
    "idle_time": 0,
    "override": {},
}
pathlib.Path(sys.argv[1]).write_text(json.dumps(manifest) + "\n", encoding="utf-8")
PY
"$phase5_bin_dir/cpak-sign" state \
  --manifest "$phase5_dir/cpak.json" \
  --origin github.com/containerpak/phase5-fixture \
  --image-digest "sha256:$(printf '1%.0s' {1..64})" \
  --generation 1 \
  --output "$phase5_dir/state"
"$phase5_bin_dir/cpak-sign" x509-sign \
  --state "$phase5_dir/state" \
  --certificate "$phase5_dir/pki/publisher.pem" \
  --chain "$phase5_dir/pki/publisher-chain.pem" \
  --key "$phase5_dir/pki/publisher-key.pem" \
  --key-passphrase-file "$phase5_dir/passphrase" \
  --output "$phase5_dir/state.cms"

if [[ "$namespace_mode" == "--sudo-namespace" ]]; then
  owner_uid="$(id -u)"
  owner_gid="$(id -g)"
  sudo --non-interactive unshare --mount --pid --fork --mount-proc \
    "$0" --inside-namespace "$phase5_dir" "$phase5_bin_dir" "$owner_uid" "$owner_gid" "$phase5_data_root" "$frontend_user" "$graphical_runtime" "$sigstore_origin" "$sigstore_oidc_token_path" "$sigstore_oidc_url_path"
elif [[ "$namespace_mode" == "--root-namespace" ]]; then
  [[ "$(id -u)" -eq 0 ]] || fail "--root-namespace requires an already-root disposable environment"
  unshare --mount --pid --fork --mount-proc \
    "$0" --inside-namespace "$phase5_dir" "$phase5_bin_dir" 0 0 "$phase5_data_root" "$frontend_user" "$graphical_runtime" "$sigstore_origin" "$sigstore_oidc_token_path" "$sigstore_oidc_url_path"
else
  unshare --user --map-root-user --mount --pid --fork --mount-proc \
    "$0" --inside-namespace "$phase5_dir" "$phase5_bin_dir" "" "" "$phase5_data_root" "$frontend_user" "$graphical_runtime" "$sigstore_origin" "$sigstore_oidc_token_path" "$sigstore_oidc_url_path"
fi

printf 'phase5: Linux core and isolated administrator harness passed\n'
