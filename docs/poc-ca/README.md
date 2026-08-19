# cpak experimental POC CA

This directory is a public, non-operational example of the certificate profile
used by the application-trust POC. It is not a default cpak trust anchor and it
does not imply public trust, publisher reputation, identity vetting, warranty,
or suitability for production use.

The checked-in material contains only public certificates, an empty test CRL,
and their manifest. The private keys used to create this static example were
disposable generation material and are not distributed. Consequently, the
static publisher certificate cannot be renewed or used to sign new releases.

For a working demonstration, generate a fresh disposable hierarchy outside the
repository:

```sh
install -m 600 /dev/null /tmp/cpak-poc-passphrase
read -r -s CPAK_POC_PASSPHRASE
printf '%s\n' "$CPAK_POC_PASSPHRASE" > /tmp/cpak-poc-passphrase
unset CPAK_POC_PASSPHRASE

go run ./hack/poc-ca \
  --output /tmp/cpak-poc-material \
  --key-passphrase-file /tmp/cpak-poc-passphrase \
  --publisher "Example Publisher"
```

Choose paths outside the checkout and remove the generated directory after the
demonstration. Never commit, publish, or reuse any `*-key.pem` file.

## Public sample files

- `root.pem`: self-signed experimental root, with path length one;
- `code-signing-intermediate.pem`: dedicated Code Signing intermediate, with
  path length zero;
- `timestamping-intermediate.pem`: separate timestamping intermediate;
- `publisher.pem`: example Code Signing leaf;
- `tsa.pem`: example timestamping-only leaf;
- `publisher.crl.pem`: empty test CRL issued by the Code Signing intermediate;
- `manifest.json`: certificate SHA-256 fingerprints and generation metadata.

The exact certificate fingerprints, not the hashes of the PEM files, are in
`manifest.json`. Administrators must compare the root fingerprint shown by
`cpak system trust-root-preview` with a value received through a separately
authenticated channel before opting in.

See [CP-CPS.md](CP-CPS.md) for the experimental policy and
[application-trust-poc-demo.md](../application-trust-poc-demo.md) for the full
signing and trust lifecycle.
