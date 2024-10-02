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

---

## Install

Follow the below steps to install the Bittensor Wallet SDK:

### For using Wallet SDK

Use this option if you want to use the Wallet SDK.

```bash
$ python3 -m venv btwallet-venv  # create a virtual env
$ source btwallet-venv/bin/activate  # activate the env
$ pip install bittensor-wallet  # install bittensor-wallet
```

### From developing with Wallet SDK

Use this option if you want to develop your application using the Wallet SDK.

```bash
python3 -m venv btwallet-venv  # create a virtual env
source venv/bin/activate  # activate the env
git clone https://github.com/opentensor/btwallet.git
python3 -m pip install -e ."[dev]" # installs dependencies for development and testing
```

OR

```bash
python3 -m venv btwallet-venv  # create a virtual env
source venv/bin/activate  # activate the env
pip install maturin
maturin develop
```

After the `maturin develop` command completes, run the below command:

```bash
pip list
```

You will see `bittensor-wallet` in the list on installed packages. This means the installation was successful.

---

## Verify your installation

Use the below method to verify that your installation was successful:

```python
from bittensor_wallet import Wallet
print(Wallet.__version__)
```

The above will print the Wallet SDK version you just installed, confirming that the installation was successful.

---

## Usage examples

**1. Create a wallet**

```python
from bittensor_wallet import Wallet

# creates wallet with name `default`
wallet = Wallet()
wallet.create()
```

The above code will create both a coldkey and a hotkey and displays the
following information, including your mnemonic **(mnemonics are replaced with `x` in the below example for security)**:

```
IMPORTANT: Store this mnemonic in a secure (preferable offline place), as anyone who has possession of this mnemonic can use it to regenerate the key and access your tokens.

The mnemonic to the new coldkey is:

forward xxxx xxx xxx xxxx xxxx xxxx xxx xx xx xx actress

You can use the mnemonic to recreate the key in case it gets lost. The command to use to regenerate the key using this mnemonic is:
btcli w regen-coldkey --mnemonic "forward xxxx xxx xxx xxxx xxxx xxxx xxx xx xx xx actress"

Specify password for key encryption:
Retype your password:

IMPORTANT: Store this mnemonic in a secure (preferable offline place), as anyone who has possession of this mnemonic can use it to regenerate the key and access your tokens.

The mnemonic to the new hotkey is:

fuel xxxx xxx xxx xxxx xxxx xxxx xxx xx xx xxx bind

You can use the mnemonic to recreate the key in case it gets lost. The command to use to regenerate the key using this mnemonic is:
btcli w regen-hotkey --mnemonic "fuel xxxx xxx xxx xxxx xxxx xxxx xxx xx xx xxx bind"

name: 'default', hotkey: 'default', path: '~/.bittensor/wallets/'
>>> print(wallet)
Wallet (Name: 'default', Hotkey: 'default', Path: '~/.bittensor/wallets/')
>>>
```

**2. Pass arguments to a class other than the default**

NEED A BETTER EXAMPLE

```
name (str): The name of the wallet, used to identify it among possibly multiple wallets.
hotkey (str): String identifier for the hotkey.
path (str): File system path where wallet keys are stored.
config (Config): Bittensor configuration object.
```

**3. Use your own config**

```python
from bittensor_wallet.config import Config
config = Config()
```

---
