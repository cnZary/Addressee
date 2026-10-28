<!--
SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
SPDX-License-Identifier: MIT OR Apache-2.0
-->

# OpenPGP card client library for use with rPGP

This crate implements OpenPGP card support for use with [rPGP](https://github.com/rpgp/rpgp/).

This is a convenience layer on top of the implementation-agnostic OpenPGP card client
library <https://crates.io/crates/openpgp-card>.

```mermaid
flowchart TD
    OCR["openpgp-card-rpgp"] --> OC["openpgp-card <br/> (OpenPGP card client library)"]
    OCR --> RPGP["rPGP <br/> (OpenPGP implementation)"]
    OC --> PCSC["card-backend-pcsc <br/> (access cards via PC/SC)"]
```