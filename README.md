## Bittensor Wallet SDK

# Install
There are a few ways to install Bittensor

1. From source for usage:
```bash
$ git clone https://github.com/opentensor/btwallet.git
$ python3 -m pip install -e bittensor_wallet/
```
2. From source for development needs:
```bash
$ git clone https://github.com/opentensor/btwallet.git
$ python3 -m venv venv  # create env
$ source venv/bin/activate  # activate env
$ pip install bittensor-wallet  # install bittensor-wallet
$ python3 -m pip install -e .[dev] # installs dependencies for development and testing
```

3. From PyPI:
```bash
$ python3 -m venv venv  # create env
$ source venv/bin/activate  # activate env
$ pip install bittensor-wallet  # install bittensor-wallet
```

# To test your installation using python
```python
from bittensor_wallet import Wallet

# creates wallet with name `default`
wallet = Wallet()
wallet.create()
```
If you want to pass arguments to the class other than the default, use the following:
```python
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
