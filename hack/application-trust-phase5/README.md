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

An already-root disposable container with the required kernel capabilities
uses the separate root mode:

```sh
./hack/application-trust-phase5/run-linux.sh --root-namespace
```

The portability workflow sets `CPAK_PHASE5_DATA_ROOT` to an anonymous Docker
volume so cpak's nested rootless OverlayFS uses a host-native backing store
rather than Docker's overlay-backed root. The volume holds disposable cpak test
state, is removed with the container, and is not a redirected developer cache.

Those modes support direct-root administration inside the private namespace.
When `CPAK_PHASE5_FRONTEND_USER` names the disposable unprivileged account, the
harness also exercises cpak's real `sudo` and `doas` re-entry. It installs
exact-command policies only in the disposable container, gives each invocation
a `PATH` containing only the frontend under test, and keeps the re-entered cpak
binary root-owned. Because binding the fixture repository to HTTPS port 443
requires a privileged network port, the process-level package lifecycle
currently runs only in these disposable-runner modes. The default user-
namespace mode still executes the core X.509 and reputation administration
lifecycle.

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
- the same warning is exercised through the built-in graphical prompt, a real
  pseudo-terminal, redirected human output, and versioned JSON; explicit
  acceptance is recorded only by the two interactive callers, while the human
  final action, reason code, and process exit agree with JSON;
- exact-manifest recovery retries the installed-but-unenrolled package in a
  real pseudo-terminal, records explicit confirmation, and does not rewrite
  package state merely to recover enrolment;
- a next-generation signed update evaluates refreshed reputation, followed by
  an actual headless binary launch, `system explain`, and `audit` using the
  recorded decision after the provider and fixture network are removed;
- the launched payload is the executable stored in the installed OCI layer,
  returns the exact expected output, and is stopped through the normal CLI;
- a systemd-equivalent service starts from the enrolled state, keeps running
  when a later launch is refused, refuses restart while state differs, and
  restarts after recovery;
- altered CMS, revoked certificates, administrator denial, blocked reputation,
  provider outage under every policy mode, signed-to-unsigned transition,
  generation replay, publisher-key rotation, and stale evidence attached to a
  changed OCI image all fail with their expected portable decisions and recover
  without corrupting the installed state;
- publisher-key rotation receives a distinct SPKI identity and cannot borrow
  the old publisher's reputation; the updated identity succeeds only after its
  own established entry is imported;
- all direct-root administration and binary/service paths work with display,
  Wayland, Xauthority, desktop-session, XDG runtime, session-bus, portal,
  keyring, and SSH-agent discovery removed, while host state remains untouched.
- real unprivileged cpak invocations add and remove the X.509 root and set,
  import, query, and clear reputation data through both `sudo` and `doas`, with
  exact argument and fingerprint policies and no graphical fallback.
- in the dedicated GitHub Actions OIDC job, two real keyless Sigstore bundles
  sign successive canonical package states, the Sigstore-only OCI referrers are
  verified against cpak's bundled trust material, and the real install and
  update complete under an exact-origin publisher policy with fresh
  `established` reputation.

The combined runtime gate is green at commit `7b72b3f` in attempt 2 of
[Portability run 32473129688](https://github.com/pietrodicaprio/cpak/actions/runs/32473129688).
Both the X.509/CMS lifecycle and the real GitHub Actions OIDC/Fulcio/Rekor
Sigstore lifecycle pass. This run also records graphical and terminal
confirmation, non-interactive refusal, human/JSON agreement, binary-only
offline launch, service restart enforcement, privilege frontends, and the
negative/recovery matrix described above. The isolated rerun used identical
source and cleared a transient runner seccomp failure.

Every trust policy generated and installed by this runtime harness uses ABI 2.
ABI 1 appears only in the frozen legacy regression fixture and is not a POC
operating policy. For AT-POL-011, strict dispatch ensures that ABI 2 cannot be
partially applied under ABI 1 semantics. The harness does not build a
historical cpak binary; that remains optional compatibility hardening and is
not a Phase 5 completion blocker.

The POC is recertified on upstream baseline `38fa798` (`v2.9.7`) at linear
reconciliation `e8737b0` and certified code commit `3149042` in
`poc/application-trust-framework`. Its POC segment after the upstream baseline
contains no merge commits. The process fixtures use Manifest v3 and
digest-pinned images. Both the X.509 and fresh keyless Sigstore jobs pass at the
certified commit in
[Portability run 33284082405](https://github.com/pietrodicaprio/cpak/actions/runs/33284082405).
