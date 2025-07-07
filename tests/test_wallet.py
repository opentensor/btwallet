import json
import time
from unittest.mock import patch

import pytest
from ansible_vault import Vault

from bittensor_wallet import Wallet, keyfile
from bittensor_wallet.errors import KeyFileError


def legacy_encrypt_keyfile_data(keyfile_data: bytes, password: str = None) -> bytes:
    vault = Vault(password)
    return vault.vault.encrypt(keyfile_data)


def create_wallet(default_updated_password):
    # create an nacl wallet
    wallet = Wallet(
        name=f"mock-{str(time.time())}",
        path="/tmp/tests_wallets/do_not_use",
    )
    with patch.object(
        keyfile,
        "ask_password_to_encrypt",
        return_value=default_updated_password,
    ):
        wallet.create()
        assert "NaCl" in str(wallet.coldkey_file)

    return wallet


def create_legacy_wallet(default_legacy_password=None, legacy_password=None):
    def _legacy_encrypt_keyfile_data(*args, **kwargs):
        args = {
            k: v
            for k, v in zip(
                legacy_encrypt_keyfile_data.__code__.co_varnames[: len(args)],
                args,
            )
        }
        kwargs = {**args, **kwargs, "password": legacy_password}
        return legacy_encrypt_keyfile_data(**kwargs)

    legacy_wallet = Wallet(
        name=f"mock-legacy-{str(time.time())}",
        path="/tmp/tests_wallets/do_not_use",
    )
    legacy_password = (
        default_legacy_password if legacy_password is None else legacy_password
    )

    # create a legacy ansible wallet
    with patch.object(
        keyfile,
        "encrypt_keyfile_data",
        new=_legacy_encrypt_keyfile_data,
        # new = TestWalletUpdate.legacy_encrypt_keyfile_data,
    ):
        legacy_wallet.create()
        assert "Ansible" in str(legacy_wallet.coldkey_file)

    return legacy_wallet


@pytest.fixture
def wallet_update_setup():
    # Setup the default passwords and wallets
    default_updated_password = "nacl_password"
    default_legacy_password = "ansible_password"
    empty_wallet = Wallet(
        name=f"mock-empty-{str(time.time())}",
        path="/tmp/tests_wallets/do_not_use",
    )
    legacy_wallet = create_legacy_wallet(
        default_legacy_password=default_legacy_password
    )
    wallet = create_wallet(default_updated_password)

    return {
        "default_updated_password": default_updated_password,
        "default_legacy_password": default_legacy_password,
        "empty_wallet": empty_wallet,
        "legacy_wallet": legacy_wallet,
        "wallet": wallet,
    }


def test_encrypt_and_decrypt():
    """Test message can be encrypted and decrypted successfully with ansible/nacl."""
    json_data = {
        "address": "This is the address.",
        "id": "This is the id.",
        "key": "This is the key.",
    }
    message = json.dumps(json_data).encode()

    # encrypt and decrypt with nacl
    encrypted_message = keyfile.encrypt_keyfile_data(message, "password")
    decrypted_message = keyfile.decrypt_keyfile_data(encrypted_message, "password")
    assert decrypted_message == message
    assert keyfile.keyfile_data_is_encrypted(encrypted_message)
    assert not keyfile.keyfile_data_is_encrypted(decrypted_message)
    assert not keyfile.keyfile_data_is_encrypted_ansible(decrypted_message)
    assert keyfile.keyfile_data_is_encrypted_nacl(encrypted_message)

    # encrypt and decrypt with legacy ansible
    encrypted_message = legacy_encrypt_keyfile_data(message, "password")
    decrypted_message = keyfile.decrypt_keyfile_data(encrypted_message, "password")
    assert decrypted_message == message
    assert keyfile.keyfile_data_is_encrypted(encrypted_message)
    assert not keyfile.keyfile_data_is_encrypted(decrypted_message)
    assert not keyfile.keyfile_data_is_encrypted_nacl(decrypted_message)
    assert keyfile.keyfile_data_is_encrypted_ansible(encrypted_message)


@pytest.fixture
def mock_wallet():
    wallet = Wallet(
        name=f"mock-{str(time.time())}",
        hotkey=f"mock-{str(time.time())}",
        path="/tmp/tests_wallets/do_not_use",
    )
    wallet.create_new_coldkey(use_password=False, overwrite=True, suppress=True)
    wallet.create_new_hotkey(use_password=False, overwrite=True, suppress=True)

    return wallet


def test_unlock_hotkey(mock_wallet):
    """Verify that `unlock_hotkey` works correctly."""

    # Call
    result = mock_wallet.unlock_hotkey()
    # Assertions
    assert result.ss58_address == mock_wallet.get_hotkey().ss58_address
    assert result.public_key == mock_wallet.get_hotkey().public_key
    assert result.ss58_format == mock_wallet.get_hotkey().ss58_format
    assert result.crypto_type == mock_wallet.get_hotkey().crypto_type


def test_unlock_coldkey(mock_wallet):
    """Verify that `unlock_coldkey` works correctly."""

    # Call
    result = mock_wallet.unlock_coldkey()
    # Assertions
    assert result.ss58_address == mock_wallet.get_coldkey().ss58_address
    assert result.public_key == mock_wallet.get_coldkey().public_key
    assert result.ss58_format == mock_wallet.get_coldkey().ss58_format
    assert result.crypto_type == mock_wallet.get_coldkey().crypto_type


def test_unlock_coldkeypub(mock_wallet):
    """Verify that `unlock_coldkeypub` works correctly."""
    # Call
    coldkeypub = mock_wallet.unlock_coldkeypub()
    hotkeypub = mock_wallet.unlock_hotkeypub()

    # Assertions
    assert coldkeypub.ss58_address == mock_wallet.get_coldkeypub().ss58_address
    assert coldkeypub.public_key == mock_wallet.get_coldkeypub().public_key
    assert coldkeypub.ss58_format == mock_wallet.get_coldkeypub().ss58_format
    assert coldkeypub.crypto_type == mock_wallet.get_coldkeypub().crypto_type

    assert hotkeypub.ss58_address == mock_wallet.get_hotkeypub().ss58_address
    assert hotkeypub.public_key == mock_wallet.get_hotkeypub().public_key
    assert hotkeypub.ss58_format == mock_wallet.get_hotkeypub().ss58_format
    assert hotkeypub.crypto_type == mock_wallet.get_hotkeypub().crypto_type


def test_wallet_string_representation_with_default_arguments():
    """Tests wallet string representation with default arguments."""
    # Call
    w = Wallet()

    # Asserts
    assert (
        str(w)
        == "Wallet (Name: 'default', Hotkey: 'default', Path: '~/.bittensor/wallets/')"
    )
    assert w.name == "default"
    assert w.hotkey_str == "default"
    assert w.path == "~/.bittensor/wallets/"


def test_wallet_string_representation_with_custom_arguments():
    """Tests wallet string representation with custom arguments."""
    # Preps
    wallet_name = "test_wallet"
    wallet_hotkey = "test_hotkey"
    wallet_path = "/tmp/tests_wallets/"

    # Call
    w = Wallet(name="test_wallet", hotkey="test_hotkey", path="/tmp/tests_wallets/")

    # Asserts
    assert (
        str(w)
        == f"Wallet (Name: '{wallet_name}', Hotkey: '{wallet_hotkey}', Path: '{wallet_path}')"
    )
    assert w.name == wallet_name
    assert w.hotkey_str == wallet_hotkey
    assert w.path == wallet_path


def test_create_coldkey_from_uri():
    """Tests create_coldkey_from_uri method."""
    # Preps
    wallet_name = "test_wallet"
    wallet_hotkey = "test_hotkey"
    wallet_path = "/tmp/tests_wallets/"

    # Call
    w = Wallet(name=wallet_name, hotkey=wallet_hotkey, path=wallet_path)
    w.create_coldkey_from_uri("//test", use_password=False, overwrite=True)

    # Asserts
    assert w.coldkey.ss58_address is not None
    assert w.coldkeypub.ss58_address is not None


def test_hotkey_coldkey_from_uri():
    """Tests create_coldkey_from_uri method."""
    # Preps
    wallet_name = "test_wallet"
    wallet_hotkey = "test_hotkey"
    wallet_path = "/tmp/tests_wallets/"

    # Call
    w = Wallet(name=wallet_name, hotkey=wallet_hotkey, path=wallet_path)
    w.create_hotkey_from_uri("//test", use_password=False, overwrite=True)

    # Asserts
    assert w.coldkey.ss58_address is not None
    assert w.coldkeypub.ss58_address is not None


def test_regenerate_hotkeypub(tmp_path):
    """Tests any type of regenerating."""

    # Preps
    wallet_name = "test_wallet_new"
    wallet_hotkey = "test_hotkey_new"
    wallet_path = (tmp_path / "test_wallets_new").resolve().as_posix()

    # Call
    w = Wallet(name=wallet_name, hotkey=wallet_hotkey, path=wallet_path)

    with pytest.raises(KeyFileError):
        _ = w.coldkey

    with pytest.raises(KeyFileError):
        _ = w.hotkey

    with pytest.raises(KeyFileError):
        _ = w.coldkeypub

    with pytest.raises(KeyFileError):
        _ = w.hotkeypub

    w.create(coldkey_use_password=False)

    ss58_coldkey = w.coldkey.ss58_address
    ss58_coldkeypub = w.coldkeypub.ss58_address
    ss58_hotkey = w.hotkey.ss58_address
    ss58_hotkeypub = w.hotkeypub.ss58_address

    w.regenerate_hotkeypub(ss58_address=ss58_hotkey, overwrite=True)

    new_ss58_hotkeypub = w.hotkeypub.ss58_address

    # Assert
    assert ss58_coldkey == ss58_coldkeypub
    assert ss58_hotkey == ss58_hotkeypub
    assert ss58_hotkeypub == new_ss58_hotkeypub
