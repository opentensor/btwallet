from bittensor_wallet import Keypair, Wallet
import pytest
import time


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


def test_keypair_type(mock_wallet):
    """Makes sure that the wallet fields coldkey, hotkey, coldkeypub are compatible with bittensor_wallet.Keypair."""
    # Preps
    wallet = mock_wallet

    # Assertions

    assert isinstance(wallet.coldkey, Keypair)
    assert isinstance(wallet.hotkey, Keypair)
    assert isinstance(wallet.coldkeypub, Keypair)
