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

3. From PyPI (**currently unavailable**):
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


## Rust
# Rust Development

To build and test the Rust components of the project, you can use the following commands:
* `maturin develop` - Builds the project.
* `cargo test` - Runs the tests.
* `cargo run` - Runs the project.
* `cargo doc --open` - Generates the documentation and opens it in the browser.
* `cargo fmt` - Formats the code.
* `cargo clippy` - Runs the linter.
* `cargo clippy --fix` - Fixes the code.

## Using the Rust components in Python
* `import btwallet`


# TODO
* password for encrypting the wallet
* create coldkey
* wrap signing into a fn and expose to python
using - create_hotkey, use sr25519::Pair =
        derive_sr25519_key(&seed, &derivation_path).expect("Failed to derive sr25519 key"); to sign a message
        ex: 
        let keypair = create_hotkey(mnemonic, "hello"); // we will need to return the keypair from create_hotkey
        let signature = keypair.sign(message);





