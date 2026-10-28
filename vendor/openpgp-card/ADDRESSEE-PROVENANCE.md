# Vendored source provenance

- Package: `openpgp-card`
- Upstream version: `0.7.0`
- Source: `https://static.crates.io/crates/openpgp-card/openpgp-card-0.7.0.crate`
- Source repository: `https://codeberg.org/openpgp-card/openpgp-card`
- VCS revision recorded by crates.io: `4a45dd221b4a4e42ec7a9f87934c76fe8fad7b89`
- Crate SHA-256: `6e49c0d2302c2f052c5d081f25100bcd89f46eec726c6674cbdeadd798bfc78d`
- License: `MIT OR Apache-2.0`

The source was extracted from the checksum-verified crates.io archive. The original `.cargo_vcs_info.json`, `Cargo.toml.orig`, normalized `Cargo.toml`, and standalone `Cargo.lock` are retained. The distribution included its standalone `Cargo.lock`; it was not generated or replaced locally.

The archive did not contain standalone license files. `LICENSE` and `LICENSES/` were copied verbatim from the repository's existing approved `licenses/openpgp-card-0.7.0/` collection. Source license and attribution headers are retained.

## Addressee local changes

- `src/ocard/apdu/command.rs`: made command data length available to the APDU layer; added Extended Length encoding for `Expect::Short` corrections and continuations; mapped a zero status length to 256 instead of 65,536; removed the unreachable encoding case; added a local-modification notice.
- `src/ocard/apdu.rs`: limited Extended Length encoding to commands whose data requires it and whose discovered capabilities permit it; preserved the selected encoding across corrections and GET RESPONSE; separated command-data limits from serialized transport limits; restricted command chaining to eligible oversized PUT DATA, key import, and PSO Decipher commands; omitted Le on non-final chain segments; prevented whole-chain and no-Le blind corrections; bounded response assembly to 65,536 bytes and 32 continuation rounds; included status bytes in extended receive-buffer hints; rejected malformed intermediate and oversized responses; redacted sensitive commands and removed response-payload logging; added host-only scripted-transport regression tests and a local-modification notice.
- `src/ocard/data.rs`: rejects Key Information shorter than the three mandatory entries or containing an incomplete entry before index-based access. The malformed-Application Related Data regression test is in the FFI management suite. Added a local-modification notice.
- `src/lib.rs`: preserves KDF transport and parsing failures during PIN verification and PIN changes instead of treating them as absent configuration; recognizes only explicit missing-data statuses for raw PIN mode. Includes the local `verification_tests.rs` tests, import formatting, and a local-modification notice.
- `src/state.rs`: propagates cached KDF read failures instead of turning them into raw PIN mode. Includes a scripted transport regression test, import formatting, and a local-modification notice.
- `src/verification_tests.rs`: adds host-only tests for raw PIN mode and KDF error handling.
- `src/ocard/commands.rs`, `src/ocard/mod.rs`, `src/ocard/keys.rs`, and `src/ocard/data/algo_info.rs`: import formatting only. No behavior changed.
- `ADDRESSEE-PROVENANCE.md`: added this provenance record.
- `LICENSE` and `LICENSES/`: added the existing approved license texts as described above.
- `rust/Cargo.toml`, outside this vendored directory: selected this path while retaining the exact `=0.7.0` version constraint. The workspace lockfile records the path dependency without a registry source or checksum; the original crate checksum is preserved above.

No upstream submission, upstream acceptance, or security audit is claimed. The regression tests use host-only scripted transports and do not establish behavior of CanoKey or any other physical OpenPGP card.

## Verification

- A completed workspace run passed 54 card-adapter library tests, including real software message operations and synthetic card transports. It did not access a physical card.
- `cargo test --manifest-path vendor/openpgp-card/Cargo.toml --locked --offline`: 44 unit tests passed and 0 failed; 1 doctest passed and 0 failed. The original manifest, standalone lockfile, and test literals were used.
- `cargo test --manifest-path rust/Cargo.toml --package openpgp-ffi --lib --locked --offline`: 41 tests passed and 0 failed. Eleven management tests cover public-only inspection, identity changes, raw PIN commands, optional absent KDF data, KDF read failures, PIN retries, reversible touch policies, and malformed Key Information. No physical card was accessed.
- `cargo clippy --manifest-path rust/Cargo.toml --workspace --all-targets --all-features --locked --offline -- -D warnings`: passed.
- `cargo clippy --manifest-path rust/Cargo.toml --locked --offline -p openpgp-card --lib -- -D warnings`: passed.
- `cargo fmt --manifest-path rust/Cargo.toml --check --package openpgp-core --package openpgp-policy --package openpgp-card-adapter --package openpgp-ffi --package uniffi-bindgen`: passed.
- `rustfmt --edition 2018 --config skip_children=true --check` passed for all nine modified source files and the added test file listed above, using the vendored formatting configuration. Formatting was not applied indiscriminately to unchanged upstream files.
- An earlier standalone `cargo clippy --manifest-path vendor/openpgp-card/Cargo.toml --all-targets --locked --offline -- -D warnings` was not clean because upstream test code uses `unwrap` and `expect`. This is not recorded as a passing all-target lint gate, and unrelated upstream tests were not rewritten or suppressed to manufacture one.
- A comparison against the retained pristine source copy found only the nine modified source files and one added test file described above, plus this provenance record and the license texts. The normalized and original manifests, standalone lockfile, and `.cargo_vcs_info.json` were verified byte-identical to that copy. The results are recorded in `build/openpgp-card-local-differences-20261027.log`.

These library and test commands were host-only and did not access a physical smart card. They do not establish CanoKey, RSA-4096 card operation, or other hardware behavior. Any separately recorded physical-card result is limited to its tested device and operation and does not generalize to other cards or algorithms.
