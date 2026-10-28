<!--
SPDX-FileCopyrightText: 2021 Wiktor Kwapisiewicz <wiktor@metacode.biz>
SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
SPDX-License-Identifier: MIT OR Apache-2.0
-->

**OpenPGP card usage with rPGP: Example apps**

*Small GnuPG replacements*

This crate can be used to decrypt OpenPGP data and to sign data
producing an OpenPGP detached signature.

First export the certificate that holds keys stored on the card:

```
$ gpg --export --armor $KEYID > cert.asc
```

Then create a test data, encrypted with GnuPG (as an example):

```
$ echo example data | gpg -ear $KEYID > encrypted.asc
```

And put the card PIN in a file called `pin`.

And then use the crate for decryption:

```
$ cargo run --example decrypt -- $CARD_ID pin < encrypted.asc
```

The `$CARD_ID` holds card ident that can be printed using `cargo
run`. It's a string that looks like `0006:12345678`. Remember that if
the GnuPG agent is holding exclusive access to the card it will not
show up. Unplugging and plugging the card again will relinquish
GnuPG's agent's hold on the card.

Signing works the same way:

```
$ echo data to be signed | cargo run --example detach-sign -- $CARD_ID pin > signature.asc
```
