<!--
SPDX-FileCopyrightText: 2021-2023 Heiko Schaefer <heiko@schaefer.name>
SPDX-License-Identifier: MIT OR Apache-2.0
-->

**OpenPGP card client library**

This crate implements a client library for the
[OpenPGP card](https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.1.pdf)
specification, in Rust.

This library provides OpenPGP library agnostic access to OpenPGP cards.
Its communication with cards is based on simple data structures that closely
match the formats defined in the OpenPGP card specification.

**Card access backends**

This crate doesn't contain code to talk to cards. Implementations of the traits
`CardBackend`/`CardTransaction` need to be provided for access to cards.

The crates [card-backend-pcsc](https://crates.io/crates/card-backend-pcsc)
and the experimental crate [card-backend-scdc](https://crates.io/crates/card-backend-scdc)
provide implementations of these traits for use with this crate.
