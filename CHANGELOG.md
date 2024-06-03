# Changelog

This project follows semantic versioning.

Possible header types:

- `Features` for any new features added, or for backwards-compatible
  changes to existing functionality.
- `Bug Fixes` for any bug fixes.
- `Breaking Changes` for any backwards-incompatible changes.

## v0.1.0-beta.5 (pending)
Nothing yet:(

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
