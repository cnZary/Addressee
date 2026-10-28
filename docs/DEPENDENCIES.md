# Dependency register

This register covers direct dependencies. `Cargo.lock` pins the complete Rust dependency graph. `scripts/audit-dependencies.py` checks every resolved package for accepted license metadata and license texts, then runs RustSec with warnings denied. Transitive dependencies are reviewed but are not required to meet a GitHub-star threshold.

Repository activity and popularity are point-in-time observations made on 2026-10-24, not guarantees. No audit result is inferred from download counts or adoption.

## Direct runtime and build dependencies

| Name | Version | Repository | Admission and maintenance evidence | License | Necessity and alternatives | Approval |
| --- | --- | --- | --- | --- | --- | --- |
| `pgp` (rPGP) | `0.21.0` | https://github.com/rpgp/rpgp | 1,089 GitHub stars when queried. Release published 2026-10-03; repository activity observed 2026-10-06. Used by substantial OpenPGP deployments; the star criterion independently admits it. | MIT OR Apache-2.0 | OpenPGP packet processing and mature cryptographic implementations. Sequoia is the principal alternative but was not selected for this rPGP-based architecture. | Accepted |
| `uniffi` | `0.32.2` | https://github.com/mozilla/uniffi-rs | 5,049 GitHub stars when queried. Mozilla project; release published 2026-09-23; repository activity observed 2026-10-16. | MPL-2.0 | Generates checked Swift/Rust FFI bindings. Hand-written C FFI is the alternative but has a larger memory-safety and maintenance burden. | Accepted |
| `openpgp-card` | `0.7.0` | https://codeberg.org/openpgp-card/openpgp-card | Four Codeberg stars when queried. Release published 2026-07-23. Used by the OpenPGP Card tools ecosystem. Small community; no project-specific independent security audit was identified in this review. | MIT OR Apache-2.0 | OpenPGP Card protocol parsing and stateful operations without vendor SDKs. A custom protocol stack would duplicate a specialized security-sensitive implementation. | Specialized exception approved 2026-10-24 |
| `openpgp-card-rpgp` | `0.8.1`, vendored compatibility work | https://codeberg.org/openpgp-card/rpgp | Two Codeberg stars when queried. Release published 2026-07-23; `0.8.0` is yanked and is not used. Used by OpenPGP Card/rPGP tooling. No project-specific independent security audit was identified in this review. | MIT OR Apache-2.0 | Connects card private-key operations to rPGP messages and certificates. Upstream `0.8.1` declares rPGP 0.20, so use is gated on a single-rPGP-0.21 compatibility implementation and tests. | Specialized exception approved 2026-10-24 |
| `rand` | `0.8.6` | https://github.com/rust-random/rand | Standard Rust random-number ecosystem with broad substantial-project adoption and the same release line used by rPGP 0.21.0. | MIT OR Apache-2.0 | Cryptographically secure operating-system randomness for key generation. | Accepted |
| `serde` | `1.0.229` | https://github.com/serde-rs/serde | Broad adoption across the Rust ecosystem and substantial maintained projects. | MIT OR Apache-2.0 | Stable data types for the machine-readable capability registry. | Accepted |
| `serde_json` | `1.0.154` | https://github.com/serde-rs/json | Broad adoption across the Rust ecosystem and substantial maintained projects. | MIT OR Apache-2.0 | JSON encoding for registry validation and diagnostics that contain no secrets. | Accepted |
| `thiserror` | `2.0.21` | https://github.com/dtolnay/thiserror | Broad adoption across maintained Rust libraries. | MIT OR Apache-2.0 | Structured library errors without exposing sensitive values. | Accepted |
| `zeroize` | `1.9.1` | https://github.com/RustCrypto/utils | RustCrypto project with broad cryptographic-project adoption, including the rPGP ecosystem. | MIT OR Apache-2.0 | Best-effort clearing of temporary secret material. It does not guarantee erasure of every compiler, OS, FFI, or hardware copy. | Accepted |
| `card-backend` | `0.2.0` | https://codeberg.org/openpgp-card/openpgp-card | Small companion trait crate in the OpenPGP Card ecosystem. It has no independent star-based admission claim; it is required to implement native transports without a vendor SDK. | MIT OR Apache-2.0 | `CardBackend` and `CardTransaction` traits for native PC/SC and Apple APDU transports. | Specialized exception approved 2026-10-24 |

`card-backend` is both a direct dependency for native transport implementations and management sessions and a transitive dependency of `openpgp-card`. Its license, maintenance, and security status remain subject to the complete lockfile audit.

`p256 0.13.2` is a test-only direct dependency of `openpgp-ffi`, with default features disabled and only its `ecdh` feature enabled. It derives the real ephemeral/recipient shared secret used by the scripted card-transport integration test; it is not an additional production dependency. The RustCrypto `elliptic-curves` repository had 879 GitHub stars when queried on 2026-10-26, exceeding the admission threshold independently of its existing use by rPGP. Its license is `Apache-2.0 OR MIT`, and its version remains identical to the already locked rPGP dependency. No independent audit of the complete P-256 implementation is claimed. The broader transitive `crypto-bigint` release blocker below still applies.

`openpgp-card 0.7.0` is pinned to a reviewed local copy for APDU boundary fixes, fail-closed KDF handling, and malformed Key Information validation. The workspace also patches crates.io so that `openpgp-card-rpgp` uses the same crate instance rather than mixing registry and local Rust types. The source archive checksum, upstream revision, license texts, local changes, and verification scope are recorded in `vendor/openpgp-card/ADDRESSEE-PROVENANCE.md`. These changes do not add a direct dependency or claim an upstream security review.

## rPGP 0.21.0 security decision

The rPGP 0.21.0 release includes fixes for short X25519 session-key panics, nested embedded-signature subpackets, and zeroization during secret-key unlocking. Addressee does not downgrade to rPGP 0.20 to accommodate the card companion crate. The vendored source provenance and every compatibility change are recorded in `vendor/openpgp-card-rpgp/ADDRESSEE-PROVENANCE.md`.

rPGP has published independent security reviews in its project history. Those reviews do not prove that this application, a new release, every transitive dependency, or the smart-card libraries are vulnerability-free. Current RustSec results must come from the checked-in lockfile rather than historical claims.

## Audit scope and reviewed advisories

The initial lockfile resolves 221 packages, including build tools and host-only dependencies. License policy normalization accepts legacy slash-separated dual-license expressions only when every selected license is on the reviewed allowlist. The collector gathered 214 of 216 third-party packages and 411 verified notice files. `cx448 0.1.1` and `hex-slice 0.1.4` still have no authoritative license/notice text at their verified source revisions, so license validation remains a release blocker rather than being marked complete. On 2026-10-24 the review was extended beyond the locked revisions: neither the upstream default branches nor the crates.io distribution archives contain any license or notice file for these two packages. The only upstream evidence is the SPDX declaration in each package's own `Cargo.toml` (`BSD-3-Clause` for `cx448`, `MIT` for `hex-slice`). No substitute text has been invented; accepting identifier-only evidence requires an explicit project-owner decision.

The 2026-10-27 review found copyright headers in two `cx448` source files referring to the original `curve25519-dalek` `LICENSE`, but that file is absent from the package and its repository tree. These references do not supply a complete current-package notice and do not resolve the blocker. The registered `hex-slice` GitHub repository now returns HTTP 404; its verified Software Heritage archive still has no license or notice file. Neither registry's most recent package version provides a replacement with collected license text.

The crates.io index still reports `pgp 0.21.0` as the newest release on 2026-10-27. The upstream rPGP `main` manifest still selects `elliptic-curve 0.13`, the P-256/P-384/P-521 0.13 series, and `cx448 0.1.1`. Although `elliptic-curve 0.14.3` is available, it is not a compatible drop-in replacement for this dependency tree. No reviewed backport of the `crypto-bigint 0.7.6` timing fixes to the locked 0.13 series has been established, and no advisory has been suppressed to conceal this limitation.

A later online RustSec retrieval failed with a network I/O error on 2026-10-27; that incomplete online attempt is not reported as a successful audit. A separate run explicitly selected the previously cloned official `https://github.com/RustSec/advisory-db.git` snapshot at revision `a78282a1414d6c28cc228c4eae3570451affb0dc` through `ADDRESSEE_RUSTSEC_DB` and `--no-fetch`. It loaded 1,378 advisories, scanned all 221 locked packages, and confirmed `RUSTSEC-2026-0387` plus the two license-text collection failures. The audit correctly returned failure. No new ignore was added. This snapshot result does not claim coverage of advisories published after the snapshot.

Two advisory IDs have narrow, version-bound review records in `scripts/audit-exceptions.json` and are printed on every audit run:

- `RUSTSEC-2023-0071` affects `rsa 0.9.10` and has no patched stable release. The documented acceptance boundary is the official RustSec workaround for local use without attacker-observable timing. Adding a network or unattended decryption interface invalidates this boundary.
- `RUSTSEC-2026-0374` marks `basic-toml 0.1.10` unmaintained. It is reached through build-time UniFFI/Askama binding generation, not the application runtime. This is a maintenance warning, not evidence of a vulnerability.

No other advisory is suppressed. Vulnerabilities, yanked packages, other maintenance warnings, unknown licenses, and stale exception records fail the audit. These reviewed exceptions do not remove the need to migrate when maintained fixes become available.

`RUSTSEC-2026-0387` is explicitly not ignored. It affects `crypto-bigint 0.5.5` through the current rPGP/RustCrypto dependency tree and describes timing variability in operations intended to be constant-time. The patched release is 0.7.6, but current rPGP and cx448 still require elliptic-curve 0.13, so there is no compatible drop-in upgrade. RustCrypto 0.14 migration has not been validated. On 2026-10-24 the project owner chose to keep this as a release blocker while development continues; production readiness and release are blocked until a compatible reviewed fix lands.

## Apple frameworks

Security, CryptoKit, LocalAuthentication, Core NFC, CryptoTokenKit where publicly available, Keychain Services, UniformTypeIdentifiers, Foundation, and SwiftUI are system frameworks rather than third-party package dependencies. No Yubico or CanoKey runtime SDK, private Apple API, cross-platform UI framework, or WebView UI is permitted.

## License and release work

MPL-2.0 and all other dependency notices must be included in distributed application licenses as applicable. A project-owner license for Addressee itself must be selected before public release; no ownership or licensing decision is implied by dependency licenses.
