# Application Trust Phase 5 Linux harness

`run-linux.sh` is an executable Phase 5 gate. It runs the repository's tests
and vet on Linux, builds the real `cpak`, `cpak-sign`, `cpak-installer`,
`cpak-storaged`, and fixture-server binaries, and then exercises the X.509,
reputation, storage, and package lifecycle CLI in a disposable mount namespace.
By default it obtains root only inside an unprivileged user namespace.

The namespace makes the caller root only inside the test and replaces
`/var/lib` with a private `tmpfs`. It also uses a temporary home and removes
display and session-bus variables. The host trust store, reputation state, and
user cpak store are therefore outside the test boundary. Failure to create the
namespace is a failed prerequisite, not a skipped or passing test.

Run it from any checkout path on a disposable Linux test machine:

```sh
./hack/application-trust-phase5/run-linux.sh
```

On a disposable CI runner that disables unprivileged user namespaces, an
explicit mode may use passwordless `sudo` only to create the private mount
namespace:

```sh
./hack/application-trust-phase5/run-linux.sh --sudo-namespace
```

That mode still runs cpak directly as root inside the private namespace. It is
not evidence for cpak's own `sudo` reinvocation path. Because binding the
fixture repository to HTTPS port 443 requires a privileged network port, the
process-level package lifecycle currently runs only in this disposable-runner
mode. The default user-namespace mode still executes the core X.509 and
reputation administration lifecycle.

The current harness proves:

- native Linux repository tests, race-enabled tests, vet, and binary builds;
- real CLI X.509 verification fails before local-root admission, succeeds
  after exact-fingerprint admission, and fails again after removal;
- process exit code and versioned JSON final decision agree;
- real CLI provider-key configuration, signed snapshot import, lookup, and
  removal with exact fingerprint binding;
- in disposable-runner mode, a real loopback HTTPS package repository and OCI
  registry with generated TLS trust, X.509 CMS referrers, and no external
  credentials;
- detached-stdin install returns `confirmation-required` without blocking even
  when `--yes` is present, and its process exit agrees with versioned JSON;
- exact-manifest recovery retries the installed-but-unenrolled package in a
  real pseudo-terminal, records explicit confirmation, and does not rewrite
  package state merely to recover enrolment;
- a next-generation signed update evaluates refreshed reputation, followed by
  offline `system explain` and `audit` using the recorded decision after the
  provider and fixture network are removed;
- all direct-root administration works without a display or session bus while
  host state remains untouched.

It does **not** prove the complete Phase 5 gate. Separate disposable-machine
runs must still record real `sudo` and `doas` reinvocation, graphical
confirmation, Sigstore install/update, binary execution, service
restart/command enforcement, and the remaining negative/recovery matrix. The
pseudo-terminal row proves terminal confirmation for X.509 only. A wrapper
named `sudo` or `doas` is not acceptable evidence for those frontend rows.
