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

## Rust Development

To build and test the Rust components of the project, you can use the following commands:
* `maturin develop` - Builds the project.
* `cargo test` - Runs the tests.
* `cargo run` - Runs the project.
* `cargo doc --open` - Generates the documentation and opens it in the browser.
* `cargo fmt` - Formats the code.
* `cargo clippy` - Runs the linter.
* `cargo clippy --fix` - Fixes the code.

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

## keypair::KeyPair

### Tests for Keypair
```python
from bittensor_wallet import Keypair as WKeypair
from substrateinterface import Keypair as SKeypair

kps = SKeypair.create_from_mnemonic("stool feel open east woman high can denial forget screen trust salt")
kpw = WKeypair.create_from_mnemonic("stool feel open east woman high can denial forget screen trust salt")
assert kps.ss58_address == kpw.ss58_address
assert kps.seed_hex == kpw.seed_hex
assert kps.public_key == kpw.public_key

kps = SKeypair.create_from_seed("0x023d5fbd7981676587a9f7232aeae1087ac7c265f9658fb643b6f5e61961dfbf")
kpw = WKeypair.create_from_seed("0x023d5fbd7981676587a9f7232aeae1087ac7c265f9658fb643b6f5e61961dfbf")
assert kps.ss58_address == kpw.ss58_address
assert kps.seed_hex == kpw.seed_hex
assert kps.public_key == kpw.public_key

# substrateinterface has a bug -> can't create the KP without `ss58_format` passed
kps = SKeypair.create_from_private_key("0x2b400f61c21cbaad4d5cb2dcbb4ef4fcdc238b98d04d48c6d2a451ebfd306c0eed845edcc69b0a19a6905afed0dd84c16ebd0f458928f2e91a6b67b95fc0b42f", ss58_format=42)
kpw = WKeypair.create_from_private_key("0x2b400f61c21cbaad4d5cb2dcbb4ef4fcdc238b98d04d48c6d2a451ebfd306c0eed845edcc69b0a19a6905afed0dd84c16ebd0f458928f2e91a6b67b95fc0b42f")
assert kps.ss58_address == kpw.ss58_address
assert kps.seed_hex == kpw.seed_hex
assert kps.public_key == kpw.public_key

kps = SKeypair.create_from_uri("//Alice")
kpw = WKeypair.create_from_uri("//Alice")
assert kps.ss58_address == kpw.ss58_address
assert kps.seed_hex == kpw.seed_hex
assert kps.public_key == kpw.public_key

# substrateinterface has a bug -> can't create the KP without `ss58_format` passed
from_private_key_new_kps = SKeypair(public_key=kps.public_key.hex(), ss58_format=42)
from_private_key_new_kpw = WKeypair(public_key=kps.public_key.hex())
assert from_private_key_new_kps.ss58_address == from_private_key_new_kpw.ss58_address
assert from_private_key_new_kps.seed_hex == from_private_key_new_kpw.seed_hex
assert from_private_key_new_kps.public_key == from_private_key_new_kpw.public_key


from_address_kps = SKeypair(ss58_address="5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY")
from_address_kpw = WKeypair(ss58_address="5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY")
assert from_address_kps.ss58_address == from_address_kpw.ss58_address
assert from_address_kps.seed_hex == from_address_kpw.seed_hex
assert from_address_kps.public_key == from_address_kpw.public_key

# check signature
assert kps.verify("asd", kpw.sign("asd")) == True

# check verify
assert kpw.verify("asd", kps.sign("asd")) == True

# check create_from_encrypted_json
from substrateinterface.base import Keypair as S_Keypair
from bittensor_wallet import Keypair as W_Keypair

data = '{"encoded":"Z1yzxASuj21ej3CANbZKc3ibDaOpQPMahTT0qkniyZgAgAAAAQAAAAgAAACSDgflXWKXrX36EmX9XcA6cRpkN+oZX30/9FhtNP17krIG/yHLKmDnL1km1W/nZ+BpC7Qid6IuBvbZeboFyewFeXsKtcoY/bRY6nx/cLB5BND9WpXXS6Enf4RXAX7vPu/BY+o2z7VwPaXyFARfyPTiqJKqLDJWm3W5ZlvK0ks8FBv66mWEBYc+lLx8jvuzDNkdD3pnV3G802OwwHTy","encoding":{"content":["pkcs8","sr25519"],"type":["scrypt","xsalsa20-poly1305"],"version":"3"},"address":"5CuByUQBWZci5AtXonuHHhcbRL3yxM5xDdJsTNaYN3vPDY6f","meta":{"genesisHash":null,"name":"test","whenCreated":1727395683981}}'
passphrase = "Password123"

skp = S_Keypair.create_from_encrypted_json(data, passphrase)
wkp = W_Keypair.create_from_encrypted_json(data, passphrase)

assert skp.ss58_format == wkp.ss58_format
assert skp.public_key == wkp.public_key
assert skp.public_key.hex() == wkp.public_key.hex()
```
### Check signature and verify with ScaleBytes
```python
from scalecodec.base import ScaleBytes
from bittensor_wallet import Keypair as WKeypair
from substrateinterface import Keypair as SKeypair

kps = SKeypair.create_from_uri("//Alice")
kpw = WKeypair.create_from_uri("//Alice")

message = ScaleBytes(b"my message")

# cross check
assert kps.verify(message, kpw.sign(message)) == True
assert kpw.verify(message, kps.sign(message)) == True

# itself check
assert kpw.verify(message, kpw.sign(message)) == True
assert kps.verify(message, kps.sign(message)) == True
```
## utils.rs

### Tests for utils' functions
```python
# check utils functions
from bittensor_wallet import get_ss58_format, is_valid_ss58_address, is_valid_ed25519_pubkey, is_valid_bittensor_address_or_public_key

# check get_ss58_format
assert get_ss58_format("5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY") == 42

# check is_valid_ss58_address
assert is_valid_ss58_address("5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY") == True
assert is_valid_ss58_address("blabla") == False

# check is_valid_ed25519_pubkey
assert is_valid_ed25519_pubkey("a"*64) == True
assert is_valid_ed25519_pubkey("5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY") == False
assert is_valid_ed25519_pubkey("0x86eb46a3f42935d901acc3b8910ca301d969b76cfc2a80f0eac733a8eda7ed24") == True
assert is_valid_ed25519_pubkey("86eb46a3f42935d901acc3b8910ca301d969b76cfc2a80f0eac733a8eda7ed24") == True
assert is_valid_ed25519_pubkey("") ==  False
try:
        is_valid_ed25519_pubkey()
except TypeError:
        # TypeError: is_valid_ed25519_pubkey() missing 1 required positional argument: 'public_key'
        ...
# check is_valid_bittensor_address_or_public_key
assert is_valid_bittensor_address_or_public_key("blabla") == False
assert is_valid_bittensor_address_or_public_key("a"*64) == False
assert is_valid_bittensor_address_or_public_key(b"5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY") == False
assert is_valid_bittensor_address_or_public_key("5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY") == True
assert is_valid_bittensor_address_or_public_key(100) == False
```

## keyfile.rs

### Tests for keyfile.rs functions

#### Test serialization and deserialization 
```python
from bittensor_wallet import Keyfile, Keypair, serialized_keypair_to_keyfile_data, deserialize_keypair_from_keyfile_data
kp = Keypair.create_from_mnemonic("stool feel open east woman high can denial forget screen trust salt")
kf_data = serialized_keypair_to_keyfile_data(kp)
assert isinstance(kf_data, bytes)
kp_2 = deserialize_keypair_from_keyfile_data(kf_data)
assert isinstance(kp_2, Keypair)
assert kp.ss58_address == kp_2.ss58_address
assert kp.seed_hex == kp_2.seed_hex
assert kp.public_key == kp_2.public_key
```

#### Test Keyfile encrypt and decrypt
```python
# test keyfile encryption and decryption 
from bittensor_wallet import Keyfile
#KF is an already encrypted key
kf = Keyfile("/Users/daniel/.bittensor/wallets/game_wallet/coldkey", name="default")
assert kf.data[:5] == b"$NACL"
kf.decrypt("testing")
#Decrypt data...
assert kf.data[1:13] == b'"publicKey":'
kf.encrypt("testing")
#Encryption data...
assert kf.data[:5] == b"$NACL"
```

#### Test Keyfile validate_password and ask_password
```python
from bittensor_wallet import validate_password, ask_password
ask_password()
    #Specify password for key encryption: {password specified here}
validate_password("test")
    # False, Password not strong enough
validate_password("asdf45as6d4f52asd6f54")
    # True
```


#### Test Keyfile keyfile_data_is_encrypted and keyfile_data_encryption_method
```python
from bittensor_wallet import Keyfile, keyfile_data_is_encrypted, keyfile_data_encryption_method
#KF is an already encrypted key NACL
kf = Keyfile("/Users/daniel/.bittensor/wallets/game_wallet/coldkey", name="default")
assert keyfile_data_is_encrypted(kf.data) == True
assert keyfile_data_encryption_method(kf.data) == 'NaCl'
```

#### Test Keyfile legacy_encrypt_keyfile_data and keyfile_data_encryption_method
```python
from bittensor_wallet import Keyfile, keyfile_data_is_encrypted, keyfile_data_encryption_method, legacy_encrypt_keyfile_data
#KF is an already encrypted key NACL
kf = Keyfile("/Users/daniel/.bittensor/wallets/validator/coldkey", name="default")
assert keyfile_data_is_encrypted(kf.data) == False
legacy_enc_kf_data = legacy_encrypt_keyfile_data(kf.data, "testing")
    # :exclamation_mark: Encrypting key with legacy encryption method...
assert keyfile_data_encryption_method(legacy_enc_kf_data) == 'Ansible Vault'
```

#### Test Keyfile get_coldkey_password_from_environment
```python
import os
from bittensor_wallet import get_coldkey_password_from_environment
assert get_coldkey_password_from_environment("some-pw") == None
os.environ["BT_COLD_PW_SOME_PW"] = "SOMEPASSWORD"
assert get_coldkey_password_from_environment("some-pw") == "SOMEPASSWORD"
```


#### Test Keyfile encrypt_keyfile_data and decrypt_keyfile_data
```python
from bittensor_wallet import Keyfile, decrypt_keyfile_data, encrypt_keyfile_data, keyfile_data_is_encrypted
kf = Keyfile("/Users/daniel/.bittensor/wallets/validator/coldkey", name="default")
assert keyfile_data_is_encrypted(kf.data) == False
encrypted_kf_data = encrypt_keyfile_data(kf.data, "somePassword")
    #Encryption data...
assert keyfile_data_is_encrypted(encrypted_kf_data) == True
decrypted_kf_data = decrypt_keyfile_data(encrypted_kf_data, "somePassword")
    #Decrypt data...
assert decrypted_kf_data == kf.data
```

### Tests for keyfile::Keyfile

#### Test Keyfile is_encrypted, decrypt, encrypt and check_and_update_encryption
```python
from bittensor_wallet import Keyfile, Keypair
kf = Keyfile("/Users/daniel/.bittensor/wallets/newkeyfile", name="default")
kp = Keypair.create_from_mnemonic("stool feel open east woman high can denial forget screen trust salt")
kf.set_keypair(kp, False, False)

assert kf.is_encrypted() == False
kf.encrypt("somepassword")
    #Encryption data...
    
assert kf.is_encrypted() == True

kf.decrypt("somepassword")
    #Decrypt data...

assert kf.is_encrypted() == False

kf.check_and_update_encryption(True, True)
    #Keyfile is not encrypted.
    #False
```

#### Test Keyfile make_dirs, is_writable, is_readable, get_keypair and exists_on_device
```python
from bittensor_wallet import Keyfile, Keypair
kf = Keyfile("/Users/daniel/.bittensor/wallets/newkeyfile", name="default")
kp = Keypair.create_from_mnemonic("stool feel open east woman high can denial forget screen trust salt")
kf.set_keypair(kp, False, False)

assert kf.exists_on_device() == False
assert kf.is_writable() == False
assert kf.is_readable() == False

kf.make_dirs()

assert kf.exists_on_device() == True
assert kf.is_writable() == True
assert kf.is_readable() == True
```

### Config parsing test
```python
import argparse
import bittensor as bt

parser = argparse.ArgumentParser(description='My parser')

bt.wallet.add_args(parser)
bt.subtensor.add_args(parser)
bt.axon.add_args(parser)
bt.logging.add_args(parser)

config = bt.config(parser)

config.wallet.name = "new_wallet_name"
config.wallet.hotkey = "new_hotkey"
config.wallet.path = "/some/not_default/path"

wallet = bt.wallet(config=config)

assert wallet.name == config.wallet.name
assert wallet.hotkey_str == config.wallet.hotkey
assert wallet.path == config.wallet.path
```