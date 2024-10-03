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

import pytest
from bittensor_wallet import utils


def test_get_ss58_format(mocker):
    """Checks that `get_ss58_format` function uses `ss58.get_ss58_format` call."""
    # Preps
    fake_ss58_addressss58_address = "5FvUhL6sQ5egLAvnyiY1n7gTuhmYg9sD3oJbvASWkpNULt3n"

    # Assertions
    assert utils.get_ss58_format(fake_ss58_addressss58_address) == 42


@pytest.mark.parametrize(
    "address, expected_result",
    [
        # Valid ss58 address for SS58_FORMAT
        ("5F3sa2TJAWMqDhXG6jhV4N8ko9rLbc4B52kmxXJoN5D3ue8w", False),
        # Valid ss58 address for default substrate format
        ("5HQV5mjTgcM9aEBi4xbnbiJdz8aez92tWyRc1U53rLYuYEMk", True),
        # Invalid ss58 address
        ("InvalidAddress", False),
    ],
)
def test_is_valid_ss58_address(address, expected_result):
    """Test `is_valid_ss58_address` function with different inputs."""

    # Mock ss58.is_valid_ss58_address
    assert utils.is_valid_ss58_address(address) == expected_result


# @pytest.mark.parametrize(
#     "address, side_effect, expected_result",
#     [
#         ("InvalidAddress", IndexError, False),  # IndexError should return False
#     ],
# )
# def test_is_valid_ss58_address_with_exceptions(
#     mocker, address, side_effect, expected_result
# ):
#     """Tests `is_valid_ss58_address` function with exceptions."""
#
#     # Mock ss58.is_valid_ss58_address to raise an exception
#     mock_ss58_is_valid = mocker.patch(
#         "substrateinterface.utils.ss58.is_valid_ss58_address"
#     )
#     mock_ss58_is_valid.side_effect = side_effect
#
#     assert utils.is_valid_ss58_address(address) == expected_result
#     mock_ss58_is_valid.assert_any_call(address, valid_ss58_format=42)


@pytest.mark.parametrize(
    "public_key, is_valid",
    [
        # Valid 64-character string public key
        ("a" * 64, True),
        # Valid 66-character string public key (with 0x prefix)
        ("a" * 66, False),
        # Valid 32-byte public key
        (b"a" * 32, False),
        # Invalid: 63-character string public key
        ("a" * 63, False),
    ],
)
def test_is_valid_ed25519_pubkey(public_key, is_valid):
    """Test is_valid_ed25519_pubkey function with different inputs."""
    assert utils.is_valid_ed25519_pubkey(public_key) == is_valid


@pytest.mark.parametrize(
    "address, excepted_result",
    [
        # Valid ss58 address `a` * 64
        ("5FvUhL6sQ5egLAvnyiY1n7gTuhmYg9sD3oJbvASWkpNULt3n", True),
        # Valid 64-character ed25519 public key
        ("0x" + "a" * 64, True),
        # Valid 32-byte ed25519 public key
        (b"a" * 32, False),
    ],
)
def test_is_valid_bittensor_address_or_public_key_integration(address, excepted_result):
    """Integration test for is_valid_bittensor_address_or_public_key function."""

    assert utils.is_valid_bittensor_address_or_public_key(address) is excepted_result
