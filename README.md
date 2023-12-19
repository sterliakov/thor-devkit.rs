# thor-devkit.rs

[![Crates.io](https://img.shields.io/crates/v/thor-devkit?logo=rust)](https://crates.io/crates/thor-devkit)
[![docs.rs](https://img.shields.io/docsrs/thor-devkit)](https://docs.rs/thor-devkit)
[![Build](https://img.shields.io/github/actions/workflow/status/sterliakov/thor-devkit.rs/build.yml?logo=github)](https://github.com/sterliakov/thor-devkit.rs/actions?query=branch%3Amaster&workflow%3abuild)
[![Test](https://img.shields.io/github/actions/workflow/status/sterliakov/thor-devkit.rs/test.yml?logo=github&label=test)](https://github.com/sterliakov/thor-devkit.rs/actions?query=branch%3Amaster&workflow%3atest)
[![Codecov](https://img.shields.io/codecov/c/github/sterliakov/thor-devkit.rs)](https://app.codecov.io/gh/sterliakov/thor-devkit.rs)

<!-- cargo-rdme start -->

Rust library to aid coding with VeChain: wallets, transactions signing,
encoding and verification, smart contract ABI interfacing, etc.

This library acts primary as a proxy to several underlying libraries,
with the addition of some VeChain-specific toolchain components.

### Usage

One of possible use cases can be transaction creation and signing.

Here is how you may approach it. Let's transfer a few VET to another account.

To do so, we need to create a transaction and encode it into broadcastable bytes.

```rust
use thor_devkit::transactions::{Transaction, Clause};
use thor_devkit::hdnode::{Mnemonic, Language, HDNode};

let transaction = Transaction {
    chain_tag: 1,
    block_ref: 0xaabbccdd,
    expiration: 32,
    clauses: vec![
        Clause {
            to: Some(
                "0x7567d83b7b8d80addcb281a71d54fc7b3364ffed"
                    .parse()
                    .unwrap(),
            ),
            value: 10000.into(),
            data: b"\x00\x00\x00\x60\x60\x60".to_vec().into(),
        },
    ],
    gas_price_coef: 128,
    gas: 21000,
    depends_on: None,
    nonce: 0xbc614e,
    reserved: None,
    signature: None,
};
let mnemonic = Mnemonic::from_phrase(
    "ignore empty bird silly journey junior ripple have guard waste between tenant",
    Language::English
).expect("Must be correct");
let wallet = HDNode::build().mnemonic(mnemonic).build().expect("Builds");
let signed = transaction.sign(&wallet.private_key().expect("Must be non-restricted").private_key());
println!("{:02x?}", signed.to_broadcastable_bytes());
```

### Examples

You can check out sample usage of this crate in the [examples/](https://github.com/sterliakov/thor-devkit.rs/tree/master/examples)
folder in the project repo on GitHub.

### Readme Docs

You can find the crate's readme documentation on the
[crates.io] page, or alternatively in the [`README.md`] file on the GitHub project repo.

[crates.io]: https://crates.io/crates/thor-devkit
[`README.md`]: https://github.com/sterliakov/thor-devkit.rs


### Contributing

Contributions are welcome! Open a pull request to fix a bug, or [open an issue][]
to discuss a new feature or change.

Check out the [Contributing][] section in the docs for more info.

[Contributing]: CONTRIBUTING.md
[open an issue]: https://github.com/sterliakov/thor-devkit.rs/issues

### License

This project is proudly licensed under the GNU General Public License v3 ([LICENSE](LICENSE)).

`thor-devkit` can be distributed according to the GNU General Public License v3. Contributions
will be accepted under the same license.

<!-- cargo-rdme end -->

## Authors

* [Stanislav Terliakov](https://github.com/sterliakov)
