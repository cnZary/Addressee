#![deny(unsafe_code)]

//! OpenPGP Card transport, vendor-neutral inspection, and CanoKey test identity checks.
//!
//! The optional `pcsc` feature enables the macOS PC/SC transport. Both inspection
//! binaries are read-only: they do not accept PINs, change card state, or retrieve
//! cardholder data or certificates. The CanoKey inspector additionally requires an
//! exact manufacturer and serial. Callers must verify USB VID/PID before invoking it.
//! AID matching alone is not authorization for destructive testing.

#[cfg(all(feature = "hardware-test", not(target_os = "ios")))]
pub mod hardware_test;
#[cfg(all(feature = "hardware-test", not(target_os = "ios")))]
pub mod hardware_upload;
mod identity;
pub mod inspection;
pub mod interaction;
pub mod pcsc;
#[cfg(not(target_os = "ios"))]
pub mod pinentry;
pub mod remote_key;
pub mod resolver;
pub mod transport;
#[cfg(all(feature = "hardware-test", not(target_os = "ios")))]
pub mod workflow_gpg;
#[cfg(all(feature = "hardware-test", not(target_os = "ios")))]
pub mod workflow_test;

#[cfg(all(feature = "hardware-test", not(target_os = "ios")))]
pub use hardware_test::{DisposableCertificate, DisposableSlot, HardwareTestError};
pub use identity::{
    CANOKEYS_MANUFACTURER, CanokeyIdentity, CardIdentity, ExpectedSerial, IdentityError,
};
