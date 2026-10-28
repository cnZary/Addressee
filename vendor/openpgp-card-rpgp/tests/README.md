<!--
SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
SPDX-License-Identifier: MIT OR Apache-2.0
-->

Integration tests for openpgp-card-rpgp.

1) Tests openpgp-card and its backends, as well as openpgp-card-rpgp.
2) Compare the behavior of different OpenPGP card firmware implementations.

# Building / Dependencies

To build this crate on Debian 11, these packages are needed: `apt install
rustc libpcsclite-dev`.

(Fedora 34: `dnf install rustc cargo pcsc-lite-devel`)

# Purpose

These tests fail in cases when essential and expected functionality of a
card is not working.

The scope of what is expected from a specific card is defined in
`config/test-cards.toml` (in particular, this configuration specifies
which algorithms we expect a card to handle for on-card key generation and
for key import, respectively - cards can't signal in detail what they
support: e.g. a card may support RSA4096 when importing keys, but not be
able to generate such keys on the card).

However, in practice, behavior of cards often diverges from the spec in
various small ways.
In many of those cases, it's not ok for these tests to fail and reject
the card's output - even when a card contradicts the OpenPGP card spec.

In such cases, these tests return information about the return values of
the card in the `TestOutput` data structure, to document that card's
behavior.

## Example for card-specific behavior that contradicts the spec

YubiKey 5 fails to handle the VERIFY command with empty data
(see OpenPGP card spec, 7.2.2: "If the command is called
without data, the actual access status of the addressed password is
returned or the access status is set to 'not verified'").

The YubiKey 5 erroneously returns Status 0x6a80 ("Incorrect parameters in
the command data field").

# Running

To access a card via pcsc, we need to install and start `pcscd`.

```
apt install pcscd
systemctl enable pcscd
systemctl start pcscd
```

(Alternatively, you could use the experimental
[scdaemon backend](https://gitlab.com/openpgp-card/openpgp-card/-/tree/scdc))

# Running tests (against emulated Gnuk via PC/SC)

In this section we will set up an "emulated Gnuk" OpenPGP card on your
computer that you can run the tests against.

## About Gnuk

Gnuk is a free implementation of the OpenPGP card spec by
[Gniibe](https://www.gniibe.org/), see: http://www.fsij.org/doc-gnuk/
(Gniibe also designs and produces
[an open hardware USB token for Gnuk](https://www.gniibe.org/tag/fst-01.html))

For testing purposes, we will run the Gnuk code in "emulated" mode
(here, "emulated" means: Gnuk will run directly on our host system,
instead of on a USB-connected device as one would usually use Gnuk).

## Building Gnuk

Install additional dependencies (Debian 11: `# apt install make usbip`,
Fedora 34: `# dnf install make usbip`)

We'll use the stable 1.2 branch of Gnuk, with the latest patches for
chopstx (which are necessary for emulated Gnuk to work with PC/SC).

Get the Gnuk source code:

```
git clone https://git.gniibe.org/cgit/gnuk/gnuk.git/
cd gnuk
git checkout STABLE-BRANCH-1-2
git submodule update --init
cd chopstx
git checkout master
cd ../src
```

Now we can build the emulated Gnuk.

We don't want to use KDF in our tests, so we disable Gnuk's default behavior
(by default, emulated Gnuk considers KDF "required") with the
`kdf_do=optional` variable (I am not aware of any OpenPGP card that
requires KDF by default, so the tests currently don't use KDF).

```
kdf_do=optional ./configure --target=GNU_LINUX --enable-factory-reset
make
```

## Running the emulated Gnuk

Emulated Gnuk connects to the system via http://usbip.sourceforge.net/.
This means that we need to load the kernel module `vhci_hcd` to connect
to a running emulated Gnuk instance.

First, we start the emulated Gnuk from a non-root account:

```
./build/gnuk --vidpid=234b:0000
```

Then, as root, we attach to the emulated Gnuk device:

```
# modprobe vhci_hcd
# usbip attach -r 127.0.0.1 -b 1-1
```

Afterwards, emulated Gnuk is connected to the system.
We can now talk to it, e.g. we can look it up with `pcsc_scan`:

```
$ pcsc_scan
Using reader plug'n play mechanism
Scanning present readers...
[..]
2: Free Software Initiative of Japan Gnuk (FSIJ-1.2.18-EMULATED) 00 00
[..]
```

## Run the card-functionality tests against the emulated Gnuk

First, we determine the `ident` of all connected OpenPGP cards (we're
looking specifically for our emulated Gnuk instance, which will show up
with the manufacturer code "FFFE", from the "Range reserved for randomly
assigned serial numbers"):

```
$ cargo run --bin list-cards
[...]

The following OpenPGP cards are connected to your system:
 FFFE:F1420A7A
```

Then we edit the test config file in `config/test-cards.toml` to use this
emulated Gnuk. The configuration should look like this:

```
[card.gnuk_emu]
backend.pcsc = "FFFE:F1420A7A"
config.keygen = ["RSA2k/32", "NIST256", "Curve25519"]
config.import = ["data/rsa2k.sec", "data/rsa4k.sec", "data/nist256.sec", "data/25519.sec"]
```

Now we can run the `card-functionality` tests, e.g. import and key generation:

```
$ cargo run --bin import
[...]

$ cargo run --bin keygen
[...]
```

# Running tests against a physical OpenPGP card token

Instead of running these tests against an emulated Gnuk, you can of course
use a physical OpenPGP card. This is actually easier to do: you can just
plug in a physical card, without needing to build or run any code.

However, be aware that these tests **delete all state on your card**!
Any **keys on your card will be deleted** when you run these tests.

To run the tests against any card, you need to explicitly configure that card
in the configuration file `config/test-cards.toml`. Without specifying a
card's identifier in the test configuration, tests will not be run
against a card, even if you have the card plugged in while running tests.
