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

import os
from typing import Optional

from Crypto.Hash import keccak

from bittensor_wallet import Keyfile, Wallet, Keypair
from .keyfile_mock import MockKeyfile


class MockWallet(Wallet):
    """
    Mocked Version of the bittensor wallet class, meant to be used for testing
    """

    def __init__(self, *args, **kwargs):
        pass

    def __new__(cls, name=None, hotkey=None, path=None, config=None, *args, **kwargs):
        r"""Init bittensor wallet object containing a hot and coldkey.
        Args:
            _mock (required=True, default=False):
                If true creates a mock wallet with random keys.
        """
        cls = super().__new__(
            cls, name=name, hotkey=hotkey, path=path, config=config, *args, **kwargs
        )
        # For mocking.
        cls._is_mock = True
        cls._mocked_coldkey_keyfile = None
        cls._mocked_hotkey_keyfile = None

        return cls

    @property
    def hotkey_file(self) -> "Keyfile":
        if self._is_mock:
            if self._mocked_hotkey_keyfile is None:
                self._mocked_hotkey_keyfile = MockKeyfile(path="MockedHotkey")
            return self._mocked_hotkey_keyfile
        else:
            wallet_path = os.path.expanduser(os.path.join(self.path, self.name))
            hotkey_path = os.path.join(wallet_path, "hotkeys", self.hotkey_str)
            return Keyfile(path=hotkey_path)

    @property
    def coldkey_file(self) -> "Keyfile":
        if self._is_mock:
            if self._mocked_coldkey_keyfile is None:
                self._mocked_coldkey_keyfile = MockKeyfile(path="MockedColdkey")
            return self._mocked_coldkey_keyfile
        else:
            wallet_path = os.path.expanduser(os.path.join(self.path, self.name))
            coldkey_path = os.path.join(wallet_path, "coldkey")
            return Keyfile(path=coldkey_path)

    @property
    def coldkeypub_file(self) -> "Keyfile":
        if self._is_mock:
            if self._mocked_coldkey_keyfile is None:
                self._mocked_coldkey_keyfile = MockKeyfile(path="MockedColdkeyPub")
            return self._mocked_coldkey_keyfile
        else:
            wallet_path = os.path.expanduser(os.path.join(self.path, self.name))
            coldkeypub_path = os.path.join(wallet_path, "coldkeypub.txt")
            return Keyfile(path=coldkeypub_path)


def get_mock_wallet(coldkey: "Keypair" = None, hotkey: "Keypair" = None):
    wallet = MockWallet(name="mock_wallet", hotkey="mock", path="/tmp/mock_wallet")

    if not coldkey:
        coldkey = Keypair.create_from_mnemonic(Keypair.generate_mnemonic())
    if not hotkey:
        hotkey = Keypair.create_from_mnemonic(Keypair.generate_mnemonic())

    wallet.set_coldkey(coldkey, encrypt=False, overwrite=True)
    wallet.set_coldkeypub(coldkey, encrypt=False, overwrite=True)
    wallet.set_hotkey(hotkey, encrypt=False, overwrite=True)

    return wallet


def get_mock_keypair(uid: int, test_name: Optional[str] = None) -> Keypair:
    """
    Returns a mock keypair from uid and optional test_name.
    If test_name is not provided, the uid is the only seed.
    If test_name is provided, the uid is hashed with the test_name to create a unique seed for the test.
    """
    if test_name is not None:
        hashed_test_name: bytes = keccak.new(
            digest_bits=256, data=test_name.encode("utf-8")
        ).digest()
        hashed_test_name_as_int: int = int.from_bytes(
            hashed_test_name, byteorder="big", signed=False
        )
        uid = uid + hashed_test_name_as_int

    return Keypair.create_from_seed(
        seed=int.to_bytes(uid, 32, "big", signed=False),
    )


def get_mock_hotkey(uid: int) -> str:
    return get_mock_keypair(uid).ss58_address


def get_mock_coldkey(uid: int) -> str:
    return get_mock_keypair(uid).ss58_address
