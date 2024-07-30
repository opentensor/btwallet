# The MIT License (MIT)
# Copyright © 2024 Opentensor Foundation
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
# documentation files (the “Software”), to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all copies or substantial portions of
# the Software.
#
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
# THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.

"""Implementation of the wallet class, which manages balances with staking and transfer. Also manages hotkey and coldkey."""

import argparse
import copy
import os
from typing import Dict, Optional, Tuple, Union, overload

from substrateinterface import Keypair
from termcolor import colored

from .config import Config
from .errors import KeyFileError
from .keyfile import Keyfile
from .utils import (
    is_valid_bittensor_address_or_public_key,
    get_ss58_format,
    SS58_FORMAT,
)

BT_WALLET_NAME = "default"
BT_WALLET_PATH = "~/.bittensor/wallets/"


def display_mnemonic_msg(keypair: Keypair, key_type: str):
    """
    Display the mnemonic and a warning message to keep the mnemonic safe.

    Args:
        keypair (Keypair): Keypair object.
        key_type (str): Type of the key (coldkey or hotkey).
    """
    mnemonic = keypair.mnemonic
    mnemonic_green = colored(mnemonic, "green")
    print(
        colored(
            "\nIMPORTANT: Store this mnemonic in a secure (preferable offline place), as anyone "
            "who has possession of this mnemonic can use it to regenerate the key and access your tokens.\n",
            "red",
        )
    )
    print("The mnemonic to the new {} is:\n\n{}\n".format(key_type, mnemonic_green))
    print(
        "You can use the mnemonic to recreate the key in case it gets lost. The command to use to regenerate the key using this mnemonic is:"
    )
    print("btcli w regen_{} --mnemonic {}".format(key_type, mnemonic))
    print("")


class Wallet:
    """
    The wallet class in the Bittensor framework handles wallet functionality, crucial for participating in the Bittensor network.

    It manages two types of keys: coldkey and hotkey, each serving different purposes in network operations. Each wallet contains a coldkey and a hotkey.

    The coldkey is the user's primary key for holding stake in their wallet and is the only way that users
    can access Tao. Coldkeys can hold tokens and should be encrypted on your device.

    The coldkey is the primary key used for securing the wallet's stake in the Bittensor network (Tao) and
    is critical for financial transactions like staking and unstaking tokens. It's recommended to keep the
    coldkey encrypted and secure, as it holds the actual tokens.

    The hotkey, in contrast, is used for operational tasks like subscribing to and setting weights in the
    network. It's linked to the coldkey through the metagraph and does not directly hold tokens, thereby
    offering a safer way to interact with the network during regular operations.

    Args:
        name (str): The name of the wallet, used to identify it among possibly multiple wallets.
        hotkey (str): String identifier for the hotkey.
        path (str): File system path where wallet keys are stored.
        config (Config): Bittensor configuration object.
        _hotkey, _coldkey, _coldkeypub (Keypair): Internal representations of the hotkey and coldkey.

    Methods:
        create_if_non_existent, create, recreate: Methods to handle the creation of wallet keys.
        get_coldkey, get_hotkey, get_coldkeypub: Methods to retrieve specific keys.
        set_coldkey, set_hotkey, set_coldkeypub: Methods to set or update keys.
        hotkey_file, coldkey_file, coldkeypub_file: Properties that return respective key file objects.
        regenerate_coldkey, regenerate_hotkey, regenerate_coldkeypub: Methods to regenerate keys from different sources.
        Config, help, add_args: Utility methods for configuration and assistance.

    The wallet class is a fundamental component for users to interact securely with the Bittensor network, facilitating both operational tasks and transactions involving value transfer across the network.

    Example Usage::

        # Create a new wallet with default coldkey and hotkey names
        my_wallet = wallet()

        # Access hotkey and coldkey
        hotkey = my_wallet.get_hotkey()
        coldkey = my_wallet.get_coldkey()

        # Set a new coldkey
        my_wallet.new_coldkey(n_words=24) # number of seed words to use

        # Update wallet hotkey
        my_wallet.set_hotkey(new_hotkey)

        # Print wallet details
        print(my_wallet)

        # Access coldkey property, must use password to unlock
        my_wallet.coldkey
    """

    def __init__(
        self,
        name: Optional[str] = None,
        hotkey: Optional[str] = None,
        path: Optional[str] = None,
        config: Optional["Config"] = None,
    ):
        """
        Initialize the bittensor wallet object containing a hot and coldkey.

        Args:
            name (str, optional): The name of the wallet to unlock for running bittensor. Defaults to ``default``.
            hotkey (str, optional): The name of hotkey used to running the miner. Defaults to ``default``.
            path (str, optional): The path to your bittensor wallets. Defaults to ``~/.bittensor/wallets/``.
            config (Config, optional): config.Config(). Defaults to ``None``.
        """
        if config is None:
            config = Wallet.config()

        self.config = copy.deepcopy(config)
        self.config.wallet.name = name or self.config.wallet.get(
            "name", Wallet.config().name
        )
        self.config.wallet.hotkey = hotkey or self.config.wallet.get(
            "hotkey", Wallet.config().hotkey
        )
        self.config.wallet.path = path or self.config.wallet.get(
            "path", Wallet.config().path
        )
        self.config.wallet.path = self.config.wallet.path.strip("'")

        self.name = self.config.wallet.name
        self.path = self.config.wallet.path
        self.hotkey_str = self.config.wallet.hotkey

        self._hotkey = None
        self._coldkey = None
        self._coldkeypub = None

    def __str__(self):
        """
        Returns a human-readable string representation of the wallet object.

        Returns:
            str: The string representation.
        """
        return f"Wallet (Name: '{self.name}', Hotkey: '{self.hotkey_str}', Path: '{self.path}')"

    def __repr__(self):
        """
        Returns the string representation of the wallet object.

        Returns:
            str: The string representation.
        """
        return f"name: '{self.name}', hotkey: '{self.hotkey_str}', path: '{self.path}'"

    @classmethod
    def config(cls) -> "Config":
        """
        Get config from the argument parser.

        Returns:
            Config: Config object.
        """
        parser = argparse.ArgumentParser()
        cls.add_args(parser)
        return Config(parser, args=[])

    @classmethod
    def help(cls):
        """
        Print help to stdout.
        """
        parser = argparse.ArgumentParser()
        cls.add_args(parser)
        print(cls.__new__.__doc__)
        parser.print_help()

    @classmethod
    def add_args(cls, parser: argparse.ArgumentParser, prefix: Optional[str] = None):
        """
        Accept specific arguments from parser.

        Args:
            parser (argparse.ArgumentParser): Argument parser object.
            prefix (str): Argument prefix.
        """
        prefix_str = "" if prefix is None else prefix + "."
        try:
            default_name = os.getenv("BT_WALLET_NAME") or BT_WALLET_NAME
            default_hotkey = os.getenv("BT_WALLET_NAME") or BT_WALLET_NAME
            default_path = os.getenv("BT_WALLET_PATH") or BT_WALLET_PATH
            parser.add_argument(
                "--" + prefix_str + "wallet.name",
                required=False,
                default=default_name,
                help="The name of the wallet to unlock for running bittensor "
                "(name mock is reserved for mocking this wallet)",
            )
            parser.add_argument(
                "--" + prefix_str + "wallet.hotkey",
                required=False,
                default=default_hotkey,
                help="The name of the wallet's hotkey.",
            )
            parser.add_argument(
                "--" + prefix_str + "wallet.path",
                required=False,
                default=default_path,
                help="The path to your bittensor wallets",
            )
        except argparse.ArgumentError:
            pass

    def create_if_non_existent(
        self, coldkey_use_password: bool = True, hotkey_use_password: bool = False
    ) -> "Wallet":
        """
        Checks for existing coldkeypub and hotkeys, and creates them if non-existent.

        Args:
            coldkey_use_password (bool, optional): Whether to use a password for coldkey. Defaults to ``True``.
            hotkey_use_password (bool, optional): Whether to use a password for hotkey. Defaults to ``False``.

        Returns:
            wallet: The wallet object.
        """
        return self.create(coldkey_use_password, hotkey_use_password)

    def create(
        self, coldkey_use_password: bool = True, hotkey_use_password: bool = False
    ) -> "Wallet":
        """
        Checks for existing coldkeypub and hotkeys, and creates them if non-existent.

        Args:
            coldkey_use_password (bool, optional): Whether to use a password for coldkey. Defaults to ``True``.
            hotkey_use_password (bool, optional): Whether to use a password for hotkey. Defaults to ``False``.

        Returns:
            wallet: The wallet object.
        """
        # ---- Setup Wallet. ----
        if (
            not self.coldkey_file.exists_on_device()
            and not self.coldkeypub_file.exists_on_device()
        ):
            self.create_new_coldkey(n_words=12, use_password=coldkey_use_password)
        else:
            print(f"ColdKey for the wallet '{self.name}' already exist.")
        if not self.hotkey_file.exists_on_device():
            self.create_new_hotkey(n_words=12, use_password=hotkey_use_password)
        else:
            print(f"HotKey for the wallet '{self.name}' already exist.")
        return self

    def recreate(
        self, coldkey_use_password: bool = True, hotkey_use_password: bool = False
    ) -> "Wallet":
        """
        Checks for existing coldkeypub and hotkeys and creates them if non-existent.

        Args:
            coldkey_use_password (bool, optional): Whether to use a password for coldkey. Defaults to ``True``.
            hotkey_use_password (bool, optional): Whether to use a password for hotkey. Defaults to ``False``.

        Returns:
            wallet: The wallet object.
        """
        # ---- Setup Wallet. ----
        self.create_new_coldkey(n_words=12, use_password=coldkey_use_password)
        self.create_new_hotkey(n_words=12, use_password=hotkey_use_password)
        return self

    @property
    def hotkey_file(self) -> "Keyfile":
        """
        Property that returns the hotkey file.

        Returns:
            Keyfile: The hotkey file.
        """
        wallet_path = os.path.expanduser(os.path.join(self.path, self.name))
        hotkey_path = os.path.join(wallet_path, "hotkeys", self.hotkey_str)
        return Keyfile(path=hotkey_path)

    @property
    def coldkey_file(self) -> "Keyfile":
        """
        Property that returns the coldkey file.

        Returns:
            Keyfile: The coldkey file.
        """
        wallet_path = os.path.expanduser(os.path.join(self.path, self.name))
        coldkey_path = os.path.join(wallet_path, "coldkey")
        return Keyfile(path=coldkey_path)

    @property
    def coldkeypub_file(self) -> "Keyfile":
        """
        Property that returns the coldkeypub file.

        Returns:
            Keyfile: The coldkeypub file.
        """
        wallet_path = os.path.expanduser(os.path.join(self.path, self.name))
        coldkeypub_path = os.path.join(wallet_path, "coldkeypub.txt")
        return Keyfile(path=coldkeypub_path)

    def set_hotkey(
        self, keypair: "Keypair", encrypt: bool = False, overwrite: bool = False
    ):
        """
        Sets the hotkey for the wallet.

        Args:
            keypair (Keypair): The hotkey keypair.
            encrypt (bool, optional): Whether to encrypt the hotkey. Defaults to ``False``.
            overwrite (bool, optional): Whether to overwrite an existing hotkey. Defaults to ``False``.
        """
        self._hotkey = keypair
        self.hotkey_file.set_keypair(keypair, encrypt=encrypt, overwrite=overwrite)

    def set_coldkeypub(
        self, keypair: "Keypair", encrypt: bool = False, overwrite: bool = False
    ):
        """
        Sets the coldkeypub for the wallet.

        Args:
            keypair (Keypair): The coldkeypub keypair.
            encrypt (bool, optional): Whether to encrypt the coldkeypub. Defaults to ``False``.
            overwrite (bool, optional): Whether to overwrite an existing coldkeypub. Defaults to ``False``.

        Returns:
            Keyfile: The coldkeypub file.
        """
        self._coldkeypub = Keypair(ss58_address=keypair.ss58_address)
        self.coldkeypub_file.set_keypair(
            self._coldkeypub, encrypt=encrypt, overwrite=overwrite
        )
        return self.coldkeypub_file

    def set_coldkey(
        self,
        keypair: "Keypair",
        encrypt: bool = True,
        overwrite: bool = False,
    ) -> "Keyfile":
        """
        Sets the coldkey for the wallet.

        Args:
            keypair (Keypair): The coldkey keypair.
            encrypt (bool, optional): Whether to encrypt the coldkey. Defaults to ``True``.
            overwrite (bool, optional): Whether to overwrite an existing coldkey. Defaults to ``False``.

            Returns:
        Keyfile: The coldkey file.
        """
        self._coldkey = keypair
        self.coldkey_file.set_keypair(
            self._coldkey, encrypt=encrypt, overwrite=overwrite
        )
        return self.coldkey_file

    def get_coldkey(self, password: Optional[str] = None) -> "Keypair":
        """
        Gets the coldkey from the wallet.

        Args:
            password (str, optional): The password to decrypt the coldkey. Defaults to ``None``.

        Returns:
            Keypair: The coldkey keypair.
        """
        return self.coldkey_file.get_keypair(password=password)

    def get_hotkey(self, password: Optional[str] = None) -> "Keypair":
        """
        Gets the hotkey from the wallet.

        Args:
            password (str, optional): The password to decrypt the hotkey. Defaults to ``None``.

        Returns:
            Keypair: The hotkey keypair.
        """
        return self.hotkey_file.get_keypair(password=password)

    def get_coldkeypub(self, password: Optional[str] = None) -> "Keypair":
        """
        Gets the coldkeypub from the wallet.

        Args:
            password (str, optional): The password to decrypt the coldkeypub. Defaults to ``None``.

        Returns:
            Keypair: The coldkeypub keypair.
        """
        return self.coldkeypub_file.get_keypair(password=password)

    @property
    def hotkey(self) -> "Keypair":
        """Loads the hotkey from wallet.path/wallet.name/hotkeys/wallet.hotkey or raises an error.

        Returns:
            hotkey (Keypair):
                hotkey loaded from Config arguments.

        Raises:
            KeyFileError: Raised if the file is corrupt of non-existent.
            CryptoKeyError: Raised if the user enters an incorrect password for an encrypted keyfile.
        """
        if self._hotkey is None:
            try:
                self._hotkey = self.hotkey_file.keypair
            except KeyFileError as error:
                print(f"KeyFileError: {error.args[0] if error.args else str(error)}.")
        return self._hotkey

    @property
    def coldkey(self) -> "Keypair":
        """Loads the coldkey from wallet.path/wallet.name/coldkey or raises an error.

        Returns:
            coldkey (Keypair): coldkey loaded from Config arguments.

        Raises:
            KeyFileError: Raised if the file is corrupt of non-existent.
            CryptoKeyError: Raised if the user enters an incorrect password for an encrypted keyfile.
        """
        if self._coldkey is None:
            try:
                self._coldkey = self.coldkey_file.keypair
            except Exception as error:
                print(f"Error: {error.args[0] if error.args else str(error)}.")

        return self._coldkey

    @property
    def coldkeypub(self) -> "Keypair":
        """Loads the coldkeypub from wallet.path/wallet.name/coldkeypub.txt or raises an error.

        Returns:
            coldkeypub (Keypair): coldkeypub loaded from Config arguments.

        Raises:
            KeyFileError: Raised if the file is corrupt of non-existent.
            CryptoKeyError: Raised if the user enters an incorrect password for an encrypted keyfile.
        """
        if self._coldkeypub is None:
            try:
                self._coldkeypub = self.coldkeypub_file.keypair
            except KeyFileError as error:
                print(f"KeyFileError: {error.args[0] if error.args else str(error)}.")
        return self._coldkeypub

    def create_coldkey_from_uri(
        self,
        uri: str,
        use_password: bool = True,
        overwrite: bool = False,
        suppress: bool = False,
    ) -> "Wallet":
        """Creates coldkey from uri string, optionally encrypts it with the user-provided password.

        Args:
            uri: (str, required): URI string to use i.e., ``/Alice`` or ``/Bob``.
            use_password (bool, optional): Is the created key password protected.
            overwrite (bool, optional): Determines if this operation overwrites the coldkey under the same path ``<wallet path>/<wallet name>/coldkey``.
            suppress (bool, optional): If ``True``, suppresses the display of the mnemonic message. Defaults to ``False``.

        Returns:
            wallet (Wallet): This object with newly created coldkey.
        """
        keypair = Keypair.create_from_uri(uri)
        if not suppress:
            display_mnemonic_msg(keypair, "coldkey")
        self.set_coldkey(keypair, encrypt=use_password, overwrite=overwrite)
        self.set_coldkeypub(keypair, overwrite=overwrite)
        return self

    def create_hotkey_from_uri(
        self,
        uri: str,
        use_password: bool = False,
        overwrite: bool = False,
        suppress: bool = False,
    ) -> "Wallet":
        """Creates hotkey from uri string, optionally encrypts it with the user-provided password.

        Args:
            uri: (str, required): URI string to use i.e., ``/Alice`` or ``/Bob``
            use_password (bool, optional): Is the created key password protected.
            overwrite (bool, optional): Determines if this operation overwrites the hotkey under the same path ``<wallet path>/<wallet name>/hotkeys/<hotkey>``.
            suppress (bool, optional): If ``True``, suppresses the display of the mnemonic message. Defaults to ``False``.

        Returns:
            wallet (Wallet): This object with newly created hotkey.
        """
        keypair = Keypair.create_from_uri(uri)
        if not suppress:
            display_mnemonic_msg(keypair, "hotkey")
        self.set_hotkey(keypair, encrypt=use_password, overwrite=overwrite)
        return self

    def unlock_coldkey(self) -> Keypair:
        """
        Unlocks the coldkey (prompts password if locked)

        Returns:
            coldkey (Keypair): the unlocked coldkey Keypair.
        """
        return self.coldkey

    def new_coldkey(
        self,
        n_words: int = 12,
        use_password: bool = True,
        overwrite: bool = False,
        suppress: bool = False,
    ) -> "Wallet":
        """Creates a new coldkey, optionally encrypts it with the user-provided password and saves to disk.

        Args:
            n_words: (int, optional): Number of mnemonic words to use.
            use_password (bool, optional): Is the created key password protected.
            overwrite (bool, optional): Determines if this operation overwrites the coldkey under the same path ``<wallet path>/<wallet name>/coldkey``.
            suppress (bool, optional): If ``True``, suppresses the display of the mnemonic message. Defaults to ``False``.

        Returns:
            wallet (Wallet): This object with newly created coldkey.
        """
        return self.create_new_coldkey(n_words, use_password, overwrite, suppress)

    def create_new_coldkey(
        self,
        n_words: int = 12,
        use_password: bool = True,
        overwrite: bool = False,
        suppress: bool = False,
    ) -> "Wallet":
        """Creates a new coldkey, optionally encrypts it with the user-provided password and saves to disk.

        Args:
            n_words: (int, optional): Number of mnemonic words to use.
            use_password (bool, optional): Is the created key password protected.
            overwrite (bool, optional): Determines if this operation overwrites the coldkey under the same path ``<wallet path>/<wallet name>/coldkey``.
            suppress (bool, optional): If ``True``, suppresses the display of the mnemonic message. Defaults to ``False``.

        Returns:
            wallet (Wallet): This object with newly created coldkey.
        """
        mnemonic = Keypair.generate_mnemonic(n_words)
        keypair = Keypair.create_from_mnemonic(mnemonic)
        if not suppress:
            display_mnemonic_msg(keypair, "coldkey")
        self.set_coldkey(keypair, encrypt=use_password, overwrite=overwrite)
        self.set_coldkeypub(keypair, overwrite=overwrite)
        return self

    def new_hotkey(
        self,
        n_words: int = 12,
        use_password: bool = False,
        overwrite: bool = False,
        suppress: bool = False,
    ) -> "Wallet":
        """Creates a new hotkey, optionally encrypts it with the user-provided password and saves to disk.

        Args:
            n_words: (int, optional): Number of mnemonic words to use.
            use_password (bool, optional): Is the created key password protected.
            overwrite (bool, optional): Determines if this operation overwrites the hotkey under the same path ``<wallet path>/<wallet name>/hotkeys/<hotkey>``.
            suppress (bool, optional): If ``True``, suppresses the display of the mnemonic message. Defaults to ``False``.

        Returns:
            wallet (Wallet):
                This object with newly created hotkey.
        """
        return self.create_new_hotkey(n_words, use_password, overwrite, suppress)

    def create_new_hotkey(
        self,
        n_words: int = 12,
        use_password: bool = False,
        overwrite: bool = False,
        suppress: bool = False,
    ) -> "Wallet":
        """Creates a new hotkey, optionally encrypts it with the user-provided password and saves to disk.

        Args:
            n_words: (int, optional): Number of mnemonic words to use.
            use_password (bool, optional): Is the created key password protected.
            overwrite (bool, optional): Will this operation overwrite the hotkey under the same path <wallet path>/<wallet name>/hotkeys/<hotkey>
            suppress (bool, optional): If ``True``, suppresses the display of the mnemonic message. Defaults to ``False``.

        Returns:
            wallet (Wallet):
                This object with newly created hotkey.
        """
        mnemonic = Keypair.generate_mnemonic(n_words)
        keypair = Keypair.create_from_mnemonic(mnemonic)

        if not suppress:
            display_mnemonic_msg(keypair, "hotkey")

        self.set_hotkey(keypair, encrypt=use_password, overwrite=overwrite)
        return self

    def regenerate_coldkeypub(
        self,
        ss58_address: Optional[str] = None,
        public_key: Optional[Union[str, bytes]] = None,
        overwrite: bool = False,
    ) -> "Wallet":
        """Regenerates the coldkeypub from the passed ``ss58_address`` or public_key and saves the file. Requires either ``ss58_address`` or public_key to be passed.

        Args:
            ss58_address: (str, optional): Address as ``ss58`` string.
            public_key: (str | bytes, optional): Public key as hex string or bytes.
            overwrite (bool, optional) (default: False): Determines if this operation overwrites the coldkeypub (if exists) under the same path ``<wallet path>/<wallet name>/coldkeypub``.

        Returns:
            wallet (Wallet):
                Newly re-generated wallet with coldkeypub.

        """
        if ss58_address is None and public_key is None:
            raise ValueError("Either ss58_address or public_key must be passed")

        if not is_valid_bittensor_address_or_public_key(
            ss58_address if ss58_address is not None else public_key
        ):
            raise ValueError(
                f"Invalid {'ss58_address' if ss58_address is not None else 'public_key'}."
            )

        if ss58_address is not None:
            ss58_format = get_ss58_format(ss58_address)
            keypair = Keypair(
                ss58_address=ss58_address,
                public_key=public_key,
                ss58_format=ss58_format,
            )
        else:
            keypair = Keypair(
                ss58_address=ss58_address,
                public_key=public_key,
                ss58_format=SS58_FORMAT,
            )

        # No need to encrypt the public key
        self.set_coldkeypub(keypair, overwrite=overwrite)
        return self

    @overload
    def regenerate_coldkey(
        self,
        mnemonic: Optional[Union[list, str]] = None,
        use_password: bool = True,
        overwrite: bool = False,
        suppress: bool = False,
    ) -> "Wallet": ...

    @overload
    def regenerate_coldkey(
        self,
        seed: Optional[str] = None,
        use_password: bool = True,
        overwrite: bool = False,
        suppress: bool = False,
    ) -> "Wallet": ...

    @overload
    def regenerate_coldkey(
        self,
        json: Optional[Tuple[Union[str, Dict], str]] = None,
        use_password: bool = True,
        overwrite: bool = False,
        suppress: bool = False,
    ) -> "Wallet": ...

    def regenerate_coldkey(
        self,
        use_password: bool = True,
        overwrite: bool = False,
        suppress: bool = False,
        **kwargs,
    ) -> "Wallet":
        """Regenerates the coldkey from the passed mnemonic or seed, or JSON encrypts it with the user's password and saves the file.

        Args:
            use_password (bool, optional): Is the created key password protected.
            overwrite (bool, optional): Determines if this operation overwrites the coldkey under the same path ``<wallet path>/<wallet name>/coldkey``.
            suppress (bool, optional): If ``True``, suppresses the display of the mnemonic message. Defaults to ``False``.
            kwargs["mnemonic"]: (Union[list, str], optional item of kwargs): Key mnemonic as list of words or string space separated words.
            kwargs["seed"]: (str, optional item of kwargs): Seed as hex string.
            kwargs["json"]: (Tuple[Union[str, Dict], str], optional item of kwargs): Restore from encrypted JSON backup as ``(json_data: Union[str, Dict], passphrase: str)``

        Returns:
            wallet (Wallet):
                This object with newly created coldkey.

        Note:
            Uses priority order: ``mnemonic > seed > json``.
        """
        if len(kwargs) == 0:
            raise ValueError("Must pass either mnemonic, seed, or json")

        # Get from kwargs
        mnemonic: Optional[Union[list, str]] = kwargs.get("mnemonic", None)
        seed: Optional[str] = kwargs.get("seed", None)
        json: Optional[Tuple[Union[str, Dict], str]] = kwargs.get("json", None)

        if mnemonic is None and seed is None and json is None:
            raise ValueError("Must pass either mnemonic, seed, or json")

        if mnemonic is not None:
            if isinstance(mnemonic, str):
                mnemonic = mnemonic.split()

            elif isinstance(mnemonic, list) and len(mnemonic) == 1:
                mnemonic = mnemonic[0].split()

            if len(mnemonic) not in [12, 15, 18, 21, 24]:
                raise ValueError(
                    "Mnemonic has invalid size. This should be 12,15,18,21 or 24 words"
                )
            keypair = Keypair.create_from_mnemonic(
                " ".join(mnemonic), ss58_format=SS58_FORMAT
            )

            if not suppress:
                display_mnemonic_msg(keypair, "coldkey")

        elif seed is not None:
            keypair = Keypair.create_from_seed(seed, ss58_format=SS58_FORMAT)

        else:
            # json is not None
            if (
                not isinstance(json, tuple)
                or len(json) != 2
                or not isinstance(json[0], (str, dict))
                or not isinstance(json[1], str)
            ):
                raise ValueError(
                    "json must be a tuple of (json_data: str | Dict, passphrase: str)"
                )

            json_data, passphrase = json
            keypair = Keypair.create_from_encrypted_json(
                json_data, passphrase, ss58_format=SS58_FORMAT
            )

        self.set_coldkey(keypair, encrypt=use_password, overwrite=overwrite)
        self.set_coldkeypub(keypair, overwrite=overwrite)
        return self

    @overload
    def regenerate_hotkey(
        self,
        *,
        mnemonic: Optional[Union[list, str]] = None,
        use_password: bool = True,
        overwrite: bool = False,
        suppress: bool = False,
    ) -> "Wallet": ...

    @overload
    def regenerate_hotkey(
        self,
        *,
        seed: Optional[str] = None,
        use_password: bool = True,
        overwrite: bool = False,
        suppress: bool = False,
    ) -> "Wallet": ...

    @overload
    def regenerate_hotkey(
        self,
        *,
        json: Optional[Tuple[Union[str, Dict], str]] = None,
        use_password: bool = True,
        overwrite: bool = False,
        suppress: bool = False,
    ) -> "Wallet": ...

    def regenerate_hotkey(
        self,
        *,
        use_password: bool = True,
        overwrite: bool = False,
        suppress: bool = False,
        **kwargs,
    ) -> "Wallet":
        """Regenerates the hotkey from passed mnemonic or seed, encrypts it with the user's password and saves the file.

        Args:
            kwargs["mnemonic"]: (Union[list, str], optional): Key mnemonic as list of words or string space separated words.
            kwargs["seed"]: (str, optional): Seed as hex string.
            kwargs["json"]: (Tuple[Union[str, Dict], str], optional): Restore from encrypted JSON backup as ``(json_data: Union[str, Dict], passphrase: str)``.
            use_password (bool, optional): Is the created key password protected.
            overwrite (bool, optional): Determines if this operation overwrites the hotkey under the same path ``<wallet path>/<wallet name>/hotkeys/<hotkey>``.
            suppress (bool, optional): If ``True``, suppresses the display of the mnemonic message. Defaults to ``False``.

        Returns:
            wallet (Wallet):
                This object with newly created hotkey.
        """
        if len(kwargs) == 0:
            raise ValueError("Must pass either mnemonic, seed, or json")

        # Get from kwargs
        mnemonic: Optional[Union[list, str]] = kwargs.get("mnemonic", None)
        seed: Optional[str] = kwargs.get("seed", None)
        json: Optional[Tuple[Union[str, Dict], str]] = kwargs.get("json", None)

        if mnemonic is None and seed is None and json is None:
            raise ValueError("Must pass either mnemonic, seed, or json")

        if mnemonic is not None:
            if isinstance(mnemonic, str):
                mnemonic = mnemonic.split()
            if len(mnemonic) not in [12, 15, 18, 21, 24]:
                raise ValueError(
                    "Mnemonic has invalid size. This should be 12, 15, 18, 21 or 24 words."
                )
            keypair = Keypair.create_from_mnemonic(
                " ".join(mnemonic), ss58_format=SS58_FORMAT
            )
            if not suppress:
                display_mnemonic_msg(keypair, "hotkey")

        elif seed is not None:
            keypair = Keypair.create_from_seed(seed, ss58_format=SS58_FORMAT)

        else:
            # json is not None
            if (
                not isinstance(json, tuple)
                or len(json) != 2
                or not isinstance(json[0], (str, dict))
                or not isinstance(json[1], str)
            ):
                raise ValueError(
                    "json must be a tuple of (json_data: str | Dict, passphrase: str)"
                )

            json_data, passphrase = json
            keypair = Keypair.create_from_encrypted_json(
                json_data, passphrase, ss58_format=SS58_FORMAT
            )

        self.set_hotkey(keypair, encrypt=use_password, overwrite=overwrite)
        return self
