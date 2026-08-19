# Offline publisher reputation POC

This runbook demonstrates the Phase 4 provider-neutral reputation workflow.
The POC consumes an administrator-selected Ed25519 authority and signed local
snapshots. It performs no network lookup and sends no telemetry.

Reputation is a separate input from signature validity, X.509 trust, origin
authorization, and administrator policy. An `established` result cannot make an
invalid or unauthorized signature acceptable. The result and its policy action
are recorded at enrolment; launch remains offline and does not recalculate
reputation.

## 1. Build the tools

```sh
go build -o ./cpak .
go build -o ./cpak-sign ./cmd/cpak-sign
```

All commands below work without a display server or session bus. Privileged
administration uses direct root execution or cpak's existing `sudo`/`doas`
transport.

## 2. Create a disposable provider authority

Keep private material outside the repository. The passphrase file must be
owned by the current user and mode `0600`.

```sh
install -d -m 0700 /path/to/private-reputation
install -m 0600 /dev/null /path/to/private-reputation/passphrase
read -r -s PROVIDER_PASSPHRASE
printf '%s\n' "$PROVIDER_PASSPHRASE" > /path/to/private-reputation/passphrase
unset PROVIDER_PASSPHRASE
./cpak-sign reputation-keygen \
  --provider cpak-poc \
  --key-passphrase-file /path/to/private-reputation/passphrase \
  --output-key /path/to/private-reputation/provider-key.pem \
  --output-authority /path/to/private-reputation/provider.json
./cpak system reputation-provider-preview /path/to/private-reputation/provider.json
```

The encrypted PKCS#8 key uses scrypt (`N=32768`, `r=8`, `p=1`) and
AES-256-GCM. `provider.json` is public; the private key and passphrase are not.

Configure the exact previewed key interactively:

```sh
./cpak system reputation-provider-set /path/to/private-reputation/provider.json
```

For unattended administration, preview first and bind the privileged operation
to the complete printed key ID:

```sh
./cpak system reputation-provider-set /path/to/private-reputation/provider.json \
  --fingerprint 'ed25519-sha256:REPLACE_WITH_EXACT_KEY_ID' --yes
```

`--yes` without the exact fingerprint is rejected.

## 3. Sign and import a snapshot

Use the normalized publisher ID reported by signature verification or
`cpak system explain`. It is an exact, stable identifier such as
`x509-spki-sha256:<64 lowercase hex>` or
`oidc-v1-sha256:<64 lowercase hex>`, never a display name.

Create `reputation-payload.json` with sorted, unique publisher IDs:

```json
{
  "sequence": 1,
  "issued_at": "2026-08-19T12:00:00Z",
  "expires_at": "2026-08-26T12:00:00Z",
  "entries": [
    {
      "publisher_id": "x509-spki-sha256:REPLACE_WITH_64_LOWERCASE_HEX",
      "status": "established",
      "reason_code": "verified-history"
    }
  ]
}
```

Sign it and preview the resulting envelope:

```sh
./cpak-sign reputation-sign \
  --authority /path/to/private-reputation/provider.json \
  --key /path/to/private-reputation/provider-key.pem \
  --key-passphrase-file /path/to/private-reputation/passphrase \
  --payload reputation-payload.json \
  --output reputation-snapshot.json
./cpak system reputation-import reputation-snapshot.json
```

An unattended import uses the full SHA-256 printed by the interactive preview:

```sh
./cpak system reputation-import reputation-snapshot.json \
  --fingerprint REPLACE_WITH_EXACT_SHA256 --yes
```

Every replacement must have a strictly larger sequence. Equal or lower
sequences are rejected even when the installed snapshot has expired. Invalid
or interrupted replacement never displaces the active authenticated record.

## 4. Inspect deterministic offline results

```sh
./cpak system reputation-status
./cpak system reputation-check 'x509-spki-sha256:REPLACE_WITH_64_LOWERCASE_HEX'
./cpak audit
./cpak system explain example.org/owner/application
```

`reputation-check` distinguishes `unknown` from `unavailable`. `audit` and
`explain` show the provider, status, provider reason code, policy action, and
policy reason code recorded when the application was enrolled. They do not
claim that reputation proves software safety.

## 5. Policy modes and headless behavior

ABI 2 policies require explicit `x509` and `reputation` sections. Modes are:

| Mode | Consequence |
| --- | --- |
| `off` | Provider is not consulted. |
| `audit` | Every result is recorded without changing the prior allow decision. |
| `warn` | Established allows; blocked denies; other results require a warning. A non-interactive headless caller receives `confirmation-required`. |
| `require-established` | Only established allows, except exact administrator exceptions for unknown or caution. |

An exception is exact across normalized publisher ID, canonical package origin,
status, and optional expiry. It cannot override blocked reputation or any
earlier signature, chain, revocation, origin, publisher, approval, or release
denial.

## 6. Move a publisher between demonstration states

Create a new payload with a larger sequence and change only the exact entry's
status and bounded reason code to `unknown`, `established`, `caution`, or
`blocked`. Sign and import it, then install or update the application to produce
a new enrolment decision. Updating the snapshot does not terminate a running
process and does not rewrite an earlier enrolment record.

To remove the POC provider and active snapshot:

```sh
./cpak system reputation-provider-clear
```

The operation previews and confirms the exact configured key. It does not
remove code-signing roots, publisher certificates, or integrity anchors.
