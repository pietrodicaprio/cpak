# v2.6.0 application-trust compatibility fixtures

These fixtures freeze the formats read and written by cpak v2.6.0 before the
application-trust POC changes storage contracts.

- `signature-state-v1.json` and `signature-state-v1.canonical` freeze the
  structured and canonical forms of `cpak.signature.state.v1`.
- `sigstore-bundle-v0.3.json` is a valid keyless Sigstore bundle generated
  with sigstore-go's ephemeral `VirtualSigstore` test authority over the
  canonical state in this directory. The frozen evidence includes a verified
  Rekor inclusion proof and RFC 3161 observer timestamp.
- `sigstore-trusted-root-v0.1.json` contains only the public test trust
  material needed to reverify that bundle. No private key is retained.
- `trust-policy-v1.json` freezes the administrator policy ABI accepted by
  v2.6.0.
- `anchor-ledger-v1.json` freezes the flat enrolment record and legacy
  `signature.state` plus `signature.bundle` representation.

The Sigstore fixtures are test-only and must never be treated as production
trust material. The ledger UID is intentionally synthetic; compatibility tests
decode it directly rather than installing it into a host authority directory.
