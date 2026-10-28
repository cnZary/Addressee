# AppleSmartCardTransport

A UI-independent Swift package for ISO 7816 APDU encoding and asynchronous transport coordination. It contains no OpenPGP application logic and no manufacturer runtime SDK.

The package separates Short APDU, Extended Length APDU, response continuation, and command chaining. `6Cxx` correction is disabled unless the caller explicitly marks the operation safe to repeat. Command chaining is disabled unless the card protocol layer enables it for a specific instruction. Continuation rounds and aggregate response sizes are bounded, and no response is silently truncated.

`APDUTransport` is implemented by platform transports. `APDUSession` supplies bounded `61xx` handling and explicit chaining policy. `NFCTransport.updateAlertMessage(_:)` updates the system reader's guidance while its session is connecting or connected, without changing the APDU interface. Callers supply their own localized, nonsensitive text; the package has no OpenPGP or localization dependency. The test suite uses scripted transports only; those tests do not establish physical-card, NFC, USB, or iOS compatibility.

## Platform status

The APDU codec and session policy are platform-independent. Core NFC and public Apple smart-card transports are integrated separately after compile-time and physical-device validation. No private Apple APIs are used.
