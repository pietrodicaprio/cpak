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

  Xvfb "$display_number" -screen 0 1024x768x24 -nolisten tcp \
    >"$phase5_dir/xvfb.log" 2>&1 &
  xvfb_pid=$!
  for _ in {1..100}; do
    if DISPLAY="$display_number" xdotool getmouselocation >/dev/null 2>&1; then
      break
    fi
    kill -0 "$xvfb_pid" 2>/dev/null || fail "the graphical test display stopped"
    sleep 0.1
  done
  DISPLAY="$display_number" xdotool getmouselocation >/dev/null 2>&1 || \
    fail "the graphical test display did not become ready"

  DISPLAY="$display_number" "$phase5_bin_dir/cpak" install \
    --branch main --yes --graphical "$origin" \
    >"$phase5_dir/install-graphical.log" 2>&1 &
  install_pid=$!
  for _ in {1..100}; do
    window_id="$(DISPLAY="$display_number" xwininfo -root -children 2>/dev/null | \
      awk '$1 ~ /^0x[0-9a-f]+$/ {print $1; exit}')"
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

  DISPLAY="$display_number" xdotool mousemove --window "$window_id" 429 479 click 1
  for _ in {1..300}; do
    kill -0 "$install_pid" 2>/dev/null || break
    sleep 0.1
  done
  if kill -0 "$install_pid" 2>/dev/null; then
    kill "$install_pid" 2>/dev/null || true
    wait "$install_pid" 2>/dev/null || true
    fail "the graphical enrolment did not finish after confirmation"
  fi
  set +e
  wait "$install_pid"
  status=$?
  set -e
  kill "$xvfb_pid" 2>/dev/null || true
  wait "$xvfb_pid" 2>/dev/null || true
  xvfb_pid=""

  [[ "$status" -eq 0 ]] || fail "graphical enrolment exited $status"
  grep -F 'confirmation accepted' "$phase5_dir/install-graphical.log" >/dev/null || \
    fail "graphical result did not record accepted confirmation"
  printf 'phase5: real graphical reputation confirmation passed\n'
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

  local origin image image_digest tls_root
  origin="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["origin"])' "$phase5_dir/fixture.json")"
  image="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["image"])' "$phase5_dir/fixture.json")"
  image_digest="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["image_digest"])' "$phase5_dir/fixture.json")"
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

  if [[ "$graphical_runtime" == "1" ]]; then
    run_graphical_enrolment "$origin"
    "$phase5_bin_dir/cpak" system explain "$origin" --json >"$phase5_dir/explain-graphical.json"
    python3 - "$phase5_dir/explain-graphical.json" <<'PY'
import json
import pathlib
import sys

document = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
trust = document.get("trust", {})
if not document.get("launch", {}).get("enrolled"):
    raise SystemExit("the graphical confirmation did not enrol the installation")
if trust.get("context") != "graphical" or trust.get("policy", {}).get("confirmation") != "accepted":
    raise SystemExit(f"unexpected graphical recorded decision: {trust!r}")
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

inside_namespace() {
  phase5_dir="$2"
  local phase5_bin_source="$3"
  phase5_bin_dir="/opt/cpak-phase5"
  cleanup_uid="${4:-}"
  cleanup_gid="${5:-}"
  local phase5_data_root="${6:-$phase5_dir/home/.local/share}"
  frontend_user="${7:-}"
  graphical_runtime="${8:-}"
  unset SUDO_UID SUDO_GID SUDO_USER
  fixture_pid=""
  xvfb_pid=""
  cleanup_namespace() {
    if [[ -n "$fixture_pid" ]]; then
      kill "$fixture_pid" 2>/dev/null || true
      wait "$fixture_pid" 2>/dev/null || true
    fi
    if [[ -n "$xvfb_pid" ]]; then
      kill "$xvfb_pid" 2>/dev/null || true
      wait "$xvfb_pid" 2>/dev/null || true
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
    require_command xdotool
    require_command xwininfo
  elif [[ -n "$graphical_runtime" ]]; then
    fail "CPAK_PHASE5_GRAPHICAL must be empty or 1"
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

[[ "$(uname -s)" == "Linux" ]] || fail "this harness must run on Linux"
for command_name in go python3 unshare mount sha256sum awk grep cp; do
  require_command "$command_name"
done
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
    "$0" --inside-namespace "$phase5_dir" "$phase5_bin_dir" "$owner_uid" "$owner_gid" "$phase5_data_root" "$frontend_user" "$graphical_runtime"
elif [[ "$namespace_mode" == "--root-namespace" ]]; then
  [[ "$(id -u)" -eq 0 ]] || fail "--root-namespace requires an already-root disposable environment"
  unshare --mount --pid --fork --mount-proc \
    "$0" --inside-namespace "$phase5_dir" "$phase5_bin_dir" 0 0 "$phase5_data_root" "$frontend_user" "$graphical_runtime"
else
  unshare --user --map-root-user --mount --pid --fork --mount-proc \
    "$0" --inside-namespace "$phase5_dir" "$phase5_bin_dir" "" "" "$phase5_data_root" "$frontend_user" "$graphical_runtime"
fi

printf 'phase5: Linux core and isolated administrator harness passed\n'
