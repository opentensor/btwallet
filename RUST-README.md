<div align="center">

# Rust Components for Bittensor Wallet SDK <!-- omit in toc -->

[![Discord Chat](https://img.shields.io/discord/308323056592486420.svg)](https://discord.gg/bittensor)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PyPI version](https://badge.fury.io/py/bittensor-wallet.svg)](https://badge.fury.io/py/bittensor-wallet)

---

## Internet-scale Neural Networks <!-- omit in toc -->

[Bittensor SDK](https://github.com/opentensor/bittensor/tree/master) • [BTCLI](https://github.com/opentensor/btcli) • [Research](https://bittensor.com/whitepaper)

</div>

The Bittensor Wallet SDK is a Python interface for a powerful Rust-based Bittensor wallet functionality. You do not need to know Rust to use this Wallet SDK. However, if you want to contribute to the Rust components of this Wallet SDK, the Rust source is located in the [src](./src) directory.

## Documentation

For a full documentation for `btwallet` Python SDK see the [Bittensor Wallet SDK section](https://docs.bittensor.com/btcli) on the developer documentation site.

## Rust development

To build the Rust components of the project, use the following commands:

- `maturin develop`: Builds the project.
- `cargo doc --open`: Generates the documentation and opens it in the browser.
- `cargo fmt`: Formats the code.
- `cargo clippy`: Runs the linter.
- `cargo clippy --fix`: Fixes the code.

## Using the Rust components in Python

```python
from bittensor_wallet import config, errors, keyfile, keypair, utils, wallet

print(utils.SS58_FORMAT)

myconf = config.Config()
print(myconf)

mywallet = wallet.Wallet(config=myconf)
print(mywallet)

try:
    mywallet.unlock_coldkey()
    mywallet.unlock_coldkeypub()
    mywallet.unlock_hotkey()
except errors.KeyFileError:
    print("Failed unlocking.")
```
