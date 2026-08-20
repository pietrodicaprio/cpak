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
document = json.loads(pathlib.Path(sys.argv[3]).read_text(encoding="utf-8"))
actual_status = int(sys.argv[4])

if document.get("schema_version") != 1:
    raise SystemExit(f"unexpected decision schema: {document.get('schema_version')!r}")
final = document.get("final", {})
if final.get("exit_code") != expected_status or actual_status != expected_status:
    raise SystemExit(
        f"exit disagreement: process={actual_status}, decision={final.get('exit_code')}, expected={expected_status}"
    )
if final.get("action") != expected_action:
    raise SystemExit(f"final action={final.get('action')!r}, expected={expected_action!r}")
if not final.get("reason_code"):
    raise SystemExit("decision has no stable final reason code")
PY
}

verify_x509() {
  local expected_status="$1"
  local expected_action="$2"
  local output="$phase5_dir/decision-$expected_status-$expected_action.json"
  local status
  set +e
  "$phase5_dir/bin/cpak" verify-signature "$phase5_dir/state.cms" \
    --state "$phase5_dir/state" --evidence-kind x509-cms --json >"$output"
  status=$?
  set -e
  assert_decision "$expected_status" "$expected_action" "$output" "$status"
}

inside_namespace() {
  phase5_dir="$2"
  export HOME="$phase5_dir/home"
  export XDG_CONFIG_HOME="$HOME/.config"
  export XDG_DATA_HOME="$HOME/.local/share"
  export XDG_STATE_HOME="$HOME/.local/state"
  unset DISPLAY WAYLAND_DISPLAY DBUS_SESSION_BUS_ADDRESS

  mkdir -p "$HOME" "$XDG_CONFIG_HOME" "$XDG_DATA_HOME" "$XDG_STATE_HOME"
  mount --make-rprivate /
  mount -t tmpfs -o mode=0755,nosuid,nodev tmpfs /var/lib
  mkdir -p /var/lib/cpak

  local root_fingerprint
  root_fingerprint="$(python3 - "$phase5_dir/pki/manifest.json" <<'PY'
import json
import pathlib
import sys
print(json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))["sha256_fingerprints"]["root.pem"])
PY
)"

  verify_x509 21 invalid
  "$phase5_dir/bin/cpak" system trust-root-add "$phase5_dir/pki/root.pem" \
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
  "$phase5_dir/bin/cpak-sign" reputation-sign \
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

  "$phase5_dir/bin/cpak" system reputation-provider-set "$phase5_dir/reputation-provider.json" \
    --fingerprint "$provider_key" --yes
  "$phase5_dir/bin/cpak" system reputation-import "$phase5_dir/reputation-snapshot.json" \
    --fingerprint "$snapshot_fingerprint" --yes
  "$phase5_dir/bin/cpak" system reputation-check "$publisher_id" | grep -F 'established' >/dev/null
  "$phase5_dir/bin/cpak" system reputation-provider-clear \
    --fingerprint "$provider_key" --yes

  "$phase5_dir/bin/cpak" system trust-root-remove "$root_fingerprint" \
    --purpose code-signing --yes
  verify_x509 21 invalid

  printf 'phase5: isolated direct-root X.509 and reputation lifecycle passed\n'
}

if [[ "${1:-}" == "--inside-namespace" ]]; then
  inside_namespace "$@"
  exit 0
fi

[[ "$(uname -s)" == "Linux" ]] || fail "this harness must run on Linux"
for command_name in go python3 unshare mount sha256sum awk grep; do
  require_command "$command_name"
done

temp_root="${TMPDIR:-/tmp}"
temp_root="${temp_root%/}"
phase5_dir="$(mktemp -d "$temp_root/cpak-phase5.XXXXXXXX")"
[[ "$phase5_dir" == "$temp_root/cpak-phase5."* ]] || fail "unsafe temporary directory"
trap 'rm -rf -- "$phase5_dir"' EXIT
chmod 0700 "$phase5_dir"
mkdir -p "$phase5_dir/bin"

cd "$repo_dir"
go test -race ./...
go test -tags cpak_ui_builtin ./pkg/desktopui
go vet ./...
CGO_ENABLED=0 go build -tags cpak_ui_builtin -trimpath -o "$phase5_dir/bin/cpak" .
CGO_ENABLED=0 go build -trimpath -o "$phase5_dir/bin/cpak-sign" ./cmd/cpak-sign
CGO_ENABLED=0 go build -tags cpak_ui_builtin -trimpath -o "$phase5_dir/bin/cpak-installer" ./cmd/cpak-installer

printf '%s\n' 'phase5-disposable-material' >"$phase5_dir/passphrase"
chmod 0600 "$phase5_dir/passphrase"
go run ./hack/poc-ca \
  --output "$phase5_dir/pki" \
  --key-passphrase-file "$phase5_dir/passphrase" \
  --publisher 'cpak Phase 5 Publisher'
"$phase5_dir/bin/cpak-sign" reputation-keygen \
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
"$phase5_dir/bin/cpak-sign" state \
  --manifest "$phase5_dir/cpak.json" \
  --origin github.com/containerpak/phase5-fixture \
  --image-digest "sha256:$(printf '1%.0s' {1..64})" \
  --generation 1 \
  --output "$phase5_dir/state"
"$phase5_dir/bin/cpak-sign" x509-sign \
  --state "$phase5_dir/state" \
  --certificate "$phase5_dir/pki/publisher.pem" \
  --chain "$phase5_dir/pki/publisher-chain.pem" \
  --key "$phase5_dir/pki/publisher-key.pem" \
  --key-passphrase-file "$phase5_dir/passphrase" \
  --output "$phase5_dir/state.cms"

unshare --user --map-root-user --mount --fork \
  "$0" --inside-namespace "$phase5_dir"

printf 'phase5: Linux core and isolated administrator harness passed\n'
