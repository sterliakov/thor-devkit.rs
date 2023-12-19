# thor-devkit.rs

[<img alt="github" src="https://img.shields.io/badge/github-sterliakov/thor--devkit.rs-8da0cb?style=for-the-badge&labelColor=555555&logo=github" height="22">](https://github.com/sterliakov/thor-devkit)
[<img alt="crates.io" src="https://img.shields.io/crates/v/thor-devkit.svg?style=for-the-badge&color=fc8d62&logo=rust" height="22">](https://crates.io/crates/thor-devkit)
[<img alt="docs.rs" src="https://img.shields.io/docsrs/thor-devkit/latest?style=for-the-badge&labelColor=555555&logoColor=white&logo=data:image/svg+xml;base64,PHN2ZyByb2xlPSJpbWciIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyIgdmlld0JveD0iMCAwIDUxMiA1MTIiPjxwYXRoIGZpbGw9IiNmNWY1ZjUiIGQ9Ik00ODguNiAyNTAuMkwzOTIgMjE0VjEwNS41YzAtMTUtOS4zLTI4LjQtMjMuNC0zMy43bC0xMDAtMzcuNWMtOC4xLTMuMS0xNy4xLTMuMS0yNS4zIDBsLTEwMCAzNy41Yy0xNC4xIDUuMy0yMy40IDE4LjctMjMuNCAzMy43VjIxNGwtOTYuNiAzNi4yQzkuMyAyNTUuNSAwIDI2OC45IDAgMjgzLjlWMzk0YzAgMTMuNiA3LjcgMjYuMSAxOS45IDMyLjJsMTAwIDUwYzEwLjEgNS4xIDIyLjEgNS4xIDMyLjIgMGwxMDMuOS01MiAxMDMuOSA1MmMxMC4xIDUuMSAyMi4xIDUuMSAzMi4yIDBsMTAwLTUwYzEyLjItNi4xIDE5LjktMTguNiAxOS45LTMyLjJWMjgzLjljMC0xNS05LjMtMjguNC0yMy40LTMzLjd6TTM1OCAyMTQuOGwtODUgMzEuOXYtNjguMmw4NS0zN3Y3My4zek0xNTQgMTA0LjFsMTAyLTM4LjIgMTAyIDM4LjJ2LjZsLTEwMiA0MS40LTEwMi00MS40di0uNnptODQgMjkxLjFsLTg1IDQyLjV2LTc5LjFsODUtMzguOHY3NS40em0wLTExMmwtMTAyIDQxLjQtMTAyLTQxLjR2LS42bDEwMi0zOC4yIDEwMiAzOC4ydi42em0yNDAgMTEybC04NSA0Mi41di03OS4xbDg1LTM4Ljh2NzUuNHptMC0xMTJsLTEwMiA0MS40LTEwMi00MS40di0uNmwxMDItMzguMiAxMDIgMzguMnYuNnoiPjwvcGF0aD48L3N2Zz4K" height="22">](https://docs.rs/thor-devkit)
[<img alt="build status" src="https://img.shields.io/github/workflow/status/sterliakov/thor-devkit/build/master?style=for-the-badge" height="22">](https://github.com/sterliakov/thor-devkit/actions?query=branch%3Amain)

<!-- cargo-rdme start -->

Rust library to aid coding with VeChain, eg. Wallets/Tx/Sign/Verify.

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

You can check out sample usage of this crate in the [examples/](https://github.com/sterliakov/thor-devkit/tree/main/examples)
folder in the project repo on GitHub.

### Readme Docs

You can find the crate's readme documentation on the
[crates.io] page, or alternatively in the [`README.md`] file on the GitHub project repo.

[crates.io]: https://crates.io/crates/thor-devkit
[`README.md`]: https://github.com/sterliakov/thor-devkit


### Contributing

Contributions are welcome! Open a pull request to fix a bug, or [open an issue][]
to discuss a new feature or change.

Check out the [Contributing][] section in the docs for more info.

[Contributing]: CONTRIBUTING.md
[open an issue]: https://github.com/sterliakov/thor-devkit/issues

### License

This project is proudly licensed under the GNU General Public License v3 ([LICENSE](LICENSE).

`thor-devkit` can be distributed according to the GNU General Public License v3. Contributions
will be accepted under the same license.

<!-- cargo-rdme end -->

## Authors

* [Stanislav Terliakov](https://github.com/sterliakov)
