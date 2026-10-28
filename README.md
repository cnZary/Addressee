# Addressee

Addressee is a native iOS OpenPGP application under active development. It uses SwiftUI for the application, Rust and rPGP for OpenPGP processing, and public Apple APIs for platform security and smart-card connectivity.

The intended deployment target is iOS 16 or later. The source tree is not yet a production release. Capability claims are recorded per operation and backend in `docs/algorithm-capabilities.json`; unverified operations are not considered supported.

## Repository layout

- `apps/ios`: native SwiftUI application and Xcode project.
- `packages`: reusable Swift packages for key providers, Secure Enclave, and APDU transport.
- `rust`: portable OpenPGP, policy, card integration, and UniFFI crates.
- `vendor`: narrowly scoped third-party compatibility patches with provenance.
- `scripts`: reproducible build, test, and dependency-audit commands.
- `tests`: interoperability and explicitly separated hardware tests.
- `docs`: security, dependency, algorithm, and hardware evidence.

## Toolchains

The repository pins Rust in `rust-toolchain.toml`. Xcode builds use the full Xcode installation through `DEVELOPER_DIR`; they do not change the system-wide Xcode selection. The current development toolchain is Xcode 27.0 and Swift 6.4.

## Build and verification

Use the repository scripts rather than invoking generated artifacts manually:

```bash
bash scripts/generate-bindings.sh
bash scripts/build-rust.sh
bash scripts/build-ios.sh
bash scripts/test.sh
```

`build-rust.sh` compiles `aarch64-apple-ios`, `aarch64-apple-ios-sim`, and `x86_64-apple-ios`, combines simulator slices, and creates a static XCFramework. `build-ios.sh` generates bindings before compiling the application in Debug configuration; pass `Release` as its first argument for a Release build. `test-ios.sh` selects an available iPhone simulator, runs the Xcode test scheme, and prints the result bundle contents. `test-text-inputs.sh` prepares a known multiline string with host-side `simctl pbcopy`, then verifies clear and complete paste actions in every long-text editor. The text-copy tests run separately through `test-copy-result.sh`, which uses host-side `simctl pbpaste` to compare the complete copied ASCII armor byte for byte after the UI action. These clipboard tests are included in the standard command. `SIMULATOR_ID` can override simulator selection. `test-apple-platform-apis.sh` verifies ARM64 iOS 16 transport linkage and NFC/smart-card declarations and is included in `test-ios.sh`; it does not access hardware or establish physical-device compatibility.

Run `python3 scripts/audit-dependencies.py` for locked license and RustSec checks. `scripts/audit-exceptions.json` documents narrowly scoped, version-bound reviews; it is not a blanket advisory bypass. `scripts/collect-license-texts.py` collects upstream notices for distribution review.

Regenerate the checked-in capability registry after changing the policy crate, then run its consistency tests:

```bash
cargo run --manifest-path rust/Cargo.toml --locked \
    --package openpgp-policy --bin generate-algorithm-capabilities \
    -- docs/algorithm-capabilities.json
```

For an explicitly selected local RustSec snapshot, set `ADDRESSEE_RUSTSEC_DB` to its checkout. The script prints the revision and passes `--no-fetch`; record the source and revision, and do not represent an old snapshot as current online coverage. This option does not suppress vulnerabilities or license failures. The currently unresolved advisory and missing license texts keep the full validation and production release blocked.

Physical smart-card tests are never part of these default commands. Secure Enclave and Keychain integration tests use separate environment opt-ins. Simulator results do not validate physical Secure Enclave, NFC, USB, or smart-card behavior.

## Safety

Normal builds and tests never access physical smart cards. Destructive hardware tests require a separate executable path, explicit runtime authorization, and exact CanoKey identity matching. They must never target a YubiKey or an unidentified card. No hardware PIN belongs in source code, command-line arguments, environment files, or logs.

Private-key export restrictions are enforced below the UI. Software export restrictions are application-level controls and must not be described as hardware non-exportability.

New Secure Enclave signing and encryption subkeys use `.biometryAny`, so private-key operations require Face ID or Touch ID without device-passcode fallback. Generation no longer asks for an OpenPGP password; the hybrid certificate's software certification primary uses a discarded one-time internal protection passphrase and cannot later certify, revoke, or recover the certificate. It is not a hardware primary or a recoverable offline-primary configuration. Existing hardware keys retain their original ACLs, and legacy binding records remain labeled as device-unlocked. The app declares a localized Face ID usage description. Interactive biometric authorization, cancellation, and the new ACL's GnuPG interoperability require a separately scheduled physical-device test; no such result is claimed yet.

## OpenPGP card connections

Import the public certificate corresponding to the card, open it in **Keys**, and choose **Link Security Key**. Select NFC or USB and the signing or decryption subkeys to bind. The connection reads the actual card identity and public slot material before saving the association, then closes rather than keeping the phone in reader mode. Each certificate can retain its own card association. **More > Hardware Key Management** lists linked devices and manages the cards themselves; it does not create certificate associations. No private-key import is needed for a card-bound certificate. PIN and touch prompts are separate from software-key passwords and are not persisted.

The public-certificate association, card identity, and component selection persist without a live session or PIN authorization. Transport is not part of that association: signing, decryption, and device management each allow NFC or USB for that operation. By default, each USB operation takes one current reader snapshot and uses the reader only when exactly one is available; no or multiple readers produce an explicit error. Enabling **More > Application Settings > Multiple Hardware Keys** displays the reader picker and requires an explicit current selection. Reader lists are not periodically polled, and the setting does not limit associations. A separate last-used preference supplies the default but never falls back to another reader or card.

An NFC private-key operation requests the card PIN before opening the system NFC reader. It then opens one session that revalidates the identity, certificate, slots, KDF, actual PIN length, and retry counters before the private-key operation. The system reader's `alertMessage` changes from scanning to card-detection/validation and then operation-in-progress guidance; successful closure explains when the card can be removed. These messages do not expose a PIN prompt behind Core NFC. Physical touch may be required during this session; the app uses conservative touch-if-requested guidance and never substitutes an app button for card touch. The prepared PIN is scoped to one operation, identity, and purpose, consumed once, and never persisted. Cancelling PIN entry does not open NFC.

USB private-key operations use a single short session with the existing native PIN/touch interactions. CryptoTokenKit transmits the exact raw APDU through its public raw-transmit API rather than the high-level APDU helper; Rust retains responsibility for length correction and bounded response continuation. Failure presentation preserves the underlying cryptographic or binding error and adds only a stage, transport, allowlisted system error code, and raw status word when available. No PIN, APDU payload, key material, plaintext, or arbitrary error description is included in diagnostic text. A linked device has a management page for explicit public-information reads, User/Admin PIN changes, and reversible Off/On touch-policy changes. Management never attaches a private-key provider; PIN attempts have retry-counter safeguards and no automatic retry after failure. Fixed and unknown touch policies are read-only. Card key generation, key import, algorithm reconfiguration, and factory reset are not implemented in the application.

The application path is vendor-neutral and uses OpenPGP Card standards rather than a CanoKey-specific interface. These software and scripted-transport capabilities do not establish physical NFC, USB-C, PIN-change, or touch-policy interoperability; each requires separate device validation.

## Status

Implementation and interoperability validation are in progress. The machine-readable registry records algorithm support separately by operation, backend, key version, and evidence level. Brainpool is not enabled for generation or cryptographic operations, and historical algorithms are constrained by security policy; a recognized algorithm name is not an end-to-end support claim.

GnuPG 2.5.24 bidirectional tests cover RSA-2048/3072/4096, NIST P-256/P-384/P-521, and legacy Curve25519. Native v6 Ed25519/X25519 and Ed448/X448 have local lifecycle and message tests, but independent evidence remains `notRun` because this GnuPG version rejects public-key algorithm identifiers 27 and 28 during import. They are not marked as fully supported.

Five physical Secure Enclave P-256 tests passed on an iPhone 15 Pro using the earlier device-unlocked ACL; these results do not validate the new biometric authorization flow. GnuPG independently verified all three signature forms, rejected a modified payload, and produced unsigned and signed encrypted messages that the device decrypted; the embedded GnuPG signature also verified. Identity trust was not established. A positively identified disposable CanoKey passed host PC/SC P-256 signing, decryption, and GnuPG public-message interoperability checks. Native NFC association remains unverified: one attempt encountered a Core NFC no-response error and a later attempt stopped at certificate-binding validation, both before PIN verification. Further interactive NFC tests require an explicitly scheduled unlocked-device session. These results do not establish compatibility with other cards or algorithms, iOS USB-C operation, or physical Extended Length/chaining behavior.

Production release remains blocked by the unresolved `crypto-bigint` advisory and missing authoritative license texts recorded in `docs/DEPENDENCIES.md`. See `docs/SECURITY.md`, `docs/HARDWARE.md`, and `docs/INTEROPERABILITY.md` for the precise evidence boundaries and unverified operations.
