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


## KeyPair

### Perfect test for Keypair
```python
from bittensor_wallet import Keypair as WKeypair
from substrateinterface import Keypair as SKeypair

kps = SKeypair.create_from_mnemonic("stool feel open east woman high can denial forget screen trust salt")
kpw = WKeypair.create_from_mnemonic("stool feel open east woman high can denial forget screen trust salt")
assert kps.ss58_address == kpw.ss58_address
assert kps.seed_hex == kpw.seed_hex
assert kps.public_key == kpw.public_key
assert kps.private_key == kpw.private_key

kps = SKeypair.create_from_seed("0x023d5fbd7981676587a9f7232aeae1087ac7c265f9658fb643b6f5e61961dfbf")
kpw = WKeypair.create_from_seed("0x023d5fbd7981676587a9f7232aeae1087ac7c265f9658fb643b6f5e61961dfbf")
assert kps.ss58_address == kpw.ss58_address
assert kps.seed_hex == kpw.seed_hex
assert kps.public_key == kpw.public_key
assert kps.private_key == kpw.private_key

# substrateinterface has a bug -> can't create the KP without `ss58_format` passed
kps = SKeypair.create_from_private_key("0x2b400f61c21cbaad4d5cb2dcbb4ef4fcdc238b98d04d48c6d2a451ebfd306c0eed845edcc69b0a19a6905afed0dd84c16ebd0f458928f2e91a6b67b95fc0b42f", ss58_format=42)
kpw = WKeypair.create_from_private_key("0x2b400f61c21cbaad4d5cb2dcbb4ef4fcdc238b98d04d48c6d2a451ebfd306c0eed845edcc69b0a19a6905afed0dd84c16ebd0f458928f2e91a6b67b95fc0b42f")
assert kps.ss58_address == kpw.ss58_address
assert kps.seed_hex == kpw.seed_hex
assert kps.public_key == kpw.public_key
assert kps.private_key == kpw.private_key

kps = SKeypair.create_from_uri("//Alice")
kpw = WKeypair.create_from_uri("//Alice")
assert kps.ss58_address == kpw.ss58_address
assert kps.seed_hex == kpw.seed_hex
assert kps.public_key == kpw.public_key
assert kps.private_key == kpw.private_key

# substrateinterface has a bug -> can't create the KP without `ss58_format` passed
from_private_key_new_kps = SKeypair(public_key=kps.public_key.hex(), ss58_format=42)
from_private_key_new_kpw = WKeypair(public_key=kps.public_key.hex())
assert from_private_key_new_kps.ss58_address == from_private_key_new_kpw.ss58_address
assert from_private_key_new_kps.seed_hex == from_private_key_new_kpw.seed_hex
assert from_private_key_new_kps.public_key == from_private_key_new_kpw.public_key
assert from_private_key_new_kps.private_key == from_private_key_new_kpw.private_key

from_address_kps = SKeypair(ss58_address="5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY")
from_address_kpw = WKeypair(ss58_address="5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY")
assert from_address_kps.ss58_address == from_address_kpw.ss58_address
assert from_address_kps.seed_hex == from_address_kpw.seed_hex
assert from_address_kps.public_key == from_address_kpw.public_key
assert from_address_kps.private_key == from_address_kpw.private_key

# check signature
assert kps.verify("asd", kpw.sign("asd")) == True

# check verify
assert kpw.verify("asd", kps.sign("asd")) == True

# check utils functions
from bittensor_wallet import get_ss58_format, is_valid_ss58_address

# check get_ss58_format
assert get_ss58_format("5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY") == 42

# check is_valid_ss58_address
assert is_valid_ss58_address("5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY") == True
assert is_valid_ss58_address("blabla") == False
```


