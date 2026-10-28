# OpenPGPAppleSecureEnclave

A UI-independent Swift package for device-bound P-256 keys. It uses only Security, CryptoKit availability checks, Foundation, and Apple's Secure Enclave.

The provider supports generation of P-256 keys, public X9.63 key export, ECDSA signatures over an already computed SHA-256 digest, and raw P-256 ECDH shared-secret computation. Private keys are generated inside the Secure Enclave. There is no raw private-key import or export API and no support claim for other curves or RSA.

OpenPGP certificate construction, subkey binding, DER-to-MPI conversion, the OpenPGP ECDH KDF, message formatting, and interoperability policy belong to the portable OpenPGP layer. The SHA-256 digest API deliberately avoids hashing the OpenPGP digest a second time.

Software fallback is never automatic. `SecureEnclave.isAvailable` and `SecKeyIsAlgorithmSupported` must both succeed for the relevant operation. A failed hardware request must not silently create a software key.

The package's explicit default access control remains `WhenUnlockedThisDeviceOnly` with `.privateKeyUsage`. The application selects `.biometryAny` for newly created subkeys, which requires Touch ID or Face ID without device-passcode fallback. `.userPresence` is a separate biometry-or-passcode policy. `.biometryCurrentSet` also excludes passcode fallback, but biometric enrollment changes can invalidate its keys. The application records whether a binding was created with the legacy device-unlocked policy or biometric authorization; it does not silently migrate old keys. Biometric cancellation and key loss are surfaced as errors, never as a software fallback.

Physical tests are opt-in and create only uniquely namespaced disposable keys, which are deleted afterward. Simulator or macOS results do not prove iOS Secure Enclave behavior or OpenPGP interoperability. Losing a device-bound encryption key may make messages encrypted only to that key permanently undecryptable; an offline primary key does not recover them.
