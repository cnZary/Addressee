# Vendored source provenance

- Package: `openpgp-card-rpgp`
- Upstream version: `0.8.1`
- Source: `https://static.crates.io/crates/openpgp-card-rpgp/openpgp-card-rpgp-0.8.1.crate`
- Source repository: `https://codeberg.org/openpgp-card/rpgp`
- VCS revision recorded by crates.io: `92e893b8afc3fedfa66f9897550edacd13323ca5`
- Crate SHA-256: `2c0a443281913544afc20d9deab29e9a60eb3b197f9d840b62d68bb1f6674a3c`
- License: `MIT OR Apache-2.0`; documentation licensing is recorded under `.reuse/` and `LICENSES/`.
- Specialized-dependency exception: approved by the project owner on 2026-10-24.

The unmodified `Cargo.toml.orig` and registry checksum are retained with the source. The normalized `Cargo.toml` initially selected rPGP 0.20. Addressee requires rPGP 0.21.0 so that the short-X25519 parsing, nested-signature-subpacket, and secret-unlocking zeroization fixes remain present.

The local compatibility work must use one rPGP 0.21.0 type system throughout the application. It must not silently downgrade rPGP, retain a second rPGP 0.20 object model, or claim hardware support from compilation alone. Every source change beyond the dependency constraint must be documented here before use.

## Addressee local changes

- `Cargo.toml`: changed only the normalized `pgp` dependency version from `0.20` to `=0.21.0`. The upstream `Cargo.toml.orig` remains unchanged.
- No changes were made to `src/`, examples, tests, or license files. The upstream 0.8.1 library source required no compatibility edits to compile against rPGP 0.21.0.
- `Cargo.lock` remains the upstream standalone-crate lockfile and therefore still records rPGP 0.20.0. Addressee builds this path dependency through `rust/Cargo.toml`, whose lockfile resolves rPGP 0.21.0; the vendored standalone lockfile is not used for that build.

## Verification

- `cargo check --manifest-path rust/Cargo.toml -p openpgp-card-adapter`, run from the Addressee workspace root, completed successfully with `openpgp-card` 0.7.0, `openpgp-card-rpgp` 0.8.1, and `pgp` 0.21.0.
- The same check with `--locked` also completed successfully. The root lockfile contains one `pgp` package entry, version 0.21.0.
- No physical card or hardware integration test was run. The vendored library has no unit tests. Its executable integration tests are ignored hardware workflows; those tests and the helper-only card targets were not selected.
