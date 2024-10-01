<div align="center">

# Bittensor Wallet SDK <!-- omit in toc -->
[![Discord Chat](https://img.shields.io/discord/308323056592486420.svg)](https://discord.gg/bittensor)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) 
[![PyPI version](https://badge.fury.io/py/bittensor-wallet.svg)](https://badge.fury.io/py/bittensor-wallet)

---

## Internet-scale Neural Networks <!-- omit in toc -->

[Bittensor SDK](https://github.com/opentensor/bittensor/tree/master) • [BTCLI](https://github.com/opentensor/btcli) • [Research](https://bittensor.com/whitepaper)

</div>

## Bittensor Wallet SDK

The Bittensor Wallet SDK is a Python interface for a powerful Rust-based Bittensor wallet functionality. You do not need to know Rust to use this Wallet SDK. However, if you want to contribute to the Rust components of this Wallet SDK, the Rust source is located in the [src](./src) directory. 

## Documentation

For a full documentation on how to use `btwallet`, see the [Bittensor Wallet SDK section](https://docs.bittensor.com/btcli) on the developer documentation site.

## Install

Follow the below steps to install the Bittensor Wallet SDK:

### If you want to use the Wallet SDK

```bash
git clone https://github.com/opentensor/btwallet.git
python3 -m pip install -e bittensor_wallet/
```

### If you want to develop your application using the Wallet SDK

```bash
git clone https://github.com/opentensor/btwallet.git
python3 -m venv venv  # create env
source venv/bin/activate  # activate env
pip install bittensor-wallet  # install bittensor-wallet
python3 -m pip install -e .[dev] # installs dependencies for development and testing
```

### From PyPI (**in preparation**)

```bash
$ python3 -m venv venv  # create env
$ source venv/bin/activate  # activate env
$ pip install bittensor-wallet  # install bittensor-wallet
```

## Verify your installation

```python
from bittensor_wallet import Wallet

# creates wallet with name `default`
wallet = Wallet()
wallet.create()
```

If you want to pass arguments to the class other than the default, use the following:

```
name (str): The name of the wallet, used to identify it among possibly multiple wallets.
hotkey (str): String identifier for the hotkey.
path (str): File system path where wallet keys are stored.
config (Config): Bittensor configuration object.
```

To use your own config, you can do it like this:

```python
from bittensor_wallet.config import Config
config = Config()
```