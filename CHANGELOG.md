# Changelog

This project follows semantic versioning.

Possible header types:

- `Features` for any new features added, or for backwards-compatible
  changes to existing functionality.
- `Bug Fixes` for any bug fixes.
- `Breaking Changes` for any backwards-incompatible changes.

## v0.2.0
* breaking: replaced several dependencies with `alloy` umbrella package. This change
  improves dependency compatibility and makes interaction of our code with external packages
  more predictable.
* breaking: the project is now released under MIT license. Previous versions can
  still be used under conditions of the previous license.
- breaking: bumped MSRV to 1.85.0
* feat: updated mainnet and testnet URLs.

## v0.1.0
- Breaking: bumped MSRV to 1.78.0
- Breaking: upgraded most of direct dependencies
- Breaking: switched to `fastrlp` RLP implementation
- Bugfix: doctests were skipped in CI

## v0.1.0-beta.4
- Fixed incorrect address encoding in presence of leading zeroes (#28).
- Added `ThorNode::eth_call` and `ThorNode::eth_call_advanced` for `view` and `pure` functions calling.
- Added a contract interaction example.

## v0.1.0-beta.3
- Increased MSRV to 1.69.0 due to incompatible upstream dependency.

### Features
- Added `TransactionBuilder` to simplify transaction preparation.

## v0.1.0-beta.2 (2023-12-23)

### Bug Fixes
- HTTP node public url made public to allow alternative URLs
-
## v0.1.0-beta.1 (2023-12-23)

### Features
- Made RLP encoding components public and rewrite it with more conscious syntax.
- Added network support for Transaction, Account and Block retrieval.

## v0.1.0-alpha.1 (2023-10-01)

- Initial Release on [crates.io] :tada:

[crates.io]: https://crates.io/crates/thor-devkit
