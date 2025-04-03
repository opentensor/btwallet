import importlib.metadata

from bittensor_wallet.bittensor_wallet import (
    Config,
    Keyfile,
    Keypair,
    Wallet,
    config,
    errors,
    keyfile,
    keypair,
    utils,
    wallet,
)

# classes
Config = Config
Keyfile = Keyfile
Keypair = Keypair
Wallet = Wallet

# modules
config = config
errors = errors
keyfile = keyfile
keypair = keypair
utils = utils
wallet = wallet

# bump version in `pyproject.toml` only
__version__ = importlib.metadata.version("bittensor-wallet")
