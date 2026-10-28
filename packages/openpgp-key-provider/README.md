# OpenPGPKeyProvider

A UI-independent capability and routing layer for private-key operations. Software keys, Secure Enclave keys, and OpenPGP cards expose only the operations their backend actually supports. Unsupported operations fail explicitly instead of falling back to another storage provider.

Signature requests contain the final OpenPGP digest, not original message content. Key-agreement requests contain only the peer public key. Secret return values use a small `SecretBytes` wrapper with best-effort clearing; this does not guarantee erasure of every Swift, Rust, operating-system, or FFI copy.

Public-key verification and recipient encryption do not require private-key access and remain in the OpenPGP engine. `exportPrivateKey` is rejected at both the provider router and individual provider boundaries for hardware keys and application-disabled software keys. Hardware policy is never inferred from UI state.

The Secure Enclave adapter implements P-256 ECDSA and P-256 ECDH only. It does not accept existing private keys. Smart-card providers must add per-card discovery, exact device identity, PIN safety, and transport-specific limits before becoming available.

This package contains routing tests with non-cryptographic test doubles. Those tests do not establish cryptographic interoperability or hardware support.
