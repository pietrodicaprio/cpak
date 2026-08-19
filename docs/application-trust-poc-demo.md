# Application Trust Phase 3 demonstration

This runbook demonstrates a disposable private PKI signing a real cpak state.
It requires a Linux environment, Go, a pushed OCI image whose registry supports
the Referrers API, the package's `cpak.json`, and credentials able to attach an
artifact to that image. It needs no developer-owned or hardware-backed key.

The commands deliberately keep three decisions separate:

1. the publisher creates a signature;
2. the registry stores the evidence;
3. the machine administrator explicitly trusts the experimental CA.

## 1. Build the tools

```sh
go build -o ./cpak ./
go build -o ./cpak-sign ./cmd/cpak-sign
```

## 2. Generate disposable private material outside the checkout

Create an owner-only passphrase file without putting its value in shell history:

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

The output says `experimental`; all `*-key.pem` files are encrypted and
owner-only. Do not copy this directory into the repository.

## 3. Build and sign the exact state

Replace the example origin, manifest, repository, digest, and generation with
the release being demonstrated:

```sh
./cpak-sign state \
  --manifest ./cpak.json \
  --origin github.com/example/application \
  --image ghcr.io/example/application \
  --image-digest sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --generation 1 \
  --output /tmp/cpak-poc-state

./cpak-sign x509-sign \
  --state /tmp/cpak-poc-state \
  --certificate /tmp/cpak-poc-material/publisher.pem \
  --chain /tmp/cpak-poc-material/publisher-chain.pem \
  --key /tmp/cpak-poc-material/publisher-key.pem \
  --key-passphrase-file /tmp/cpak-poc-passphrase \
  --output /tmp/cpak-poc-state.cms
```

`x509-sign` reports the stable SPKI publisher ID and explicitly states that the
CA assurance is experimental. The private key is supplied through
`crypto.Signer`; CMS remains detached from the canonical state.

## 4. Attach after publication-time validation

The publisher may validate against the generated root without importing it
into machine policy. This one-off `--trust-root` option only gates the upload:

```sh
export CPAK_REGISTRY_USERNAME='example'
read -r -s CPAK_REGISTRY_PASSWORD
export CPAK_REGISTRY_PASSWORD

./cpak-sign attach \
  --image ghcr.io/example/application \
  --state /tmp/cpak-poc-state \
  --bundle /tmp/cpak-poc-state.cms \
  --evidence-kind x509-cms \
  --trust-root /tmp/cpak-poc-material/root.pem

unset CPAK_REGISTRY_PASSWORD CPAK_REGISTRY_USERNAME
```

The referrer uses artifact type `application/vnd.cpak.signature.x509.v1` and a
single `application/pkcs7-signature` layer.

## 5. Prove explicit opt-in

Before import, verification must fail as an untrusted Code Signing chain:

```sh
./cpak verify-signature /tmp/cpak-poc-state.cms \
  --state /tmp/cpak-poc-state \
  --evidence-kind x509-cms
```

Preview the certificate and compare its fingerprint with `manifest.json` over
a separately authenticated channel. Then explicitly import it:

```sh
./cpak system trust-root-preview /tmp/cpak-poc-material/root.pem \
  --purpose code-signing

./cpak system trust-root-add /tmp/cpak-poc-material/root.pem \
  --purpose code-signing \
  --fingerprint LOWERCASE_SHA256_FROM_PREVIEW \
  --yes

./cpak verify-signature /tmp/cpak-poc-state.cms \
  --state /tmp/cpak-poc-state \
  --evidence-kind x509-cms
```

The successful report identifies the X.509 publisher, local root source,
signing-time status, and revocation status. It still makes no reputation claim.

## 6. Enrol and exercise removal

With the image, manifest, and origin published consistently, install normally:

```sh
./cpak system set-signatures required
./cpak install github.com/example/application --yes
./cpak system explain github.com/example/application
```

Record the root fingerprint and remove only that explicit trust decision:

```sh
./cpak system trust-root-remove LOWERCASE_SHA256_FROM_PREVIEW \
  --purpose code-signing \
  --yes

./cpak verify-signature /tmp/cpak-poc-state.cms \
  --state /tmp/cpak-poc-state \
  --evidence-kind x509-cms

./cpak system explain github.com/example/application
```

Full verification now fails as untrusted. The existing ledger entry remains
readable: trust-root removal does not rewrite enrolment history. Restore the
host's prior signature policy when the demonstration is finished.

Finally remove the disposable CA directory and passphrase file. They are not
part of the published example and must not be reused.
