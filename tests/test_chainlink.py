# Copyright (c) 2024, Circle Internet Financial, LTD. All rights reserved.
#
#  SPDX-License-Identifier: Apache-2.0

"""Unit tests for chainlink.py — pure/utility functions only."""

import sys
from io import StringIO
from unittest.mock import MagicMock, mock_open, patch

import pytest

# Mock gnupg before importing chainlink (which imports chainmail)
mock_gpg_instance = MagicMock()
mock_gnupg = MagicMock()
mock_gnupg.GPG.return_value = mock_gpg_instance
sys.modules["gnupg"] = mock_gnupg

CONFIG = {
    "pgp": {"bin": "/usr/bin/gpg"},
    "chainmail": {"hostname": "https://chainmail.example.com"},
    "chainlink": {
        "contract_file": "src/Chainmail.sol",
        "register_email_address": "registerEmailAddress(bytes32,address,bytes32)",
        "register_email_message": "registerEmailMessage(bytes32)",
        "email_address_info": "emailAddressInfo(bytes32)",
        "verify_email_message": "verifyEmailMessage(bytes32,bytes32)",
        "local_env_file": ".chainmail_env",
    },
    "local_key_file": "keys.yaml",
}

KEY = {
    "testnet_account": {"private_key": "0xabc"},
    "testnet_sender": {"private_key": "0xdef", "address": "0x123"},
    "rpc_url": "http://localhost:8545",
    "etherscan_api_key": "",
}

_yaml_returns = [CONFIG, CONFIG, KEY]
_yaml_call_count = 0

_original_open = open


def _selective_open(filename, *args, **kwargs):
    """Only intercept config/key file opens, let everything else through."""
    if isinstance(filename, str) and (
        filename.endswith("config.yaml") or filename.endswith("keys.yaml")
    ):
        return StringIO("mocked")
    return _original_open(filename, *args, **kwargs)


def _yaml_side_effect(*args, **kwargs):
    global _yaml_call_count
    idx = min(_yaml_call_count, len(_yaml_returns) - 1)
    _yaml_call_count += 1
    return _yaml_returns[idx]


with patch("builtins.open", _selective_open):
    with patch("yaml.safe_load", side_effect=_yaml_side_effect):
        import chainlink


class TestHashEmailAddress:
    """Tests for hash_email_address()"""

    def test_deterministic(self):
        h1 = chainlink.hash_email_address("user@example.com")
        h2 = chainlink.hash_email_address("user@example.com")
        assert h1 == h2

    def test_case_insensitive(self):
        h1 = chainlink.hash_email_address("User@Example.COM")
        h2 = chainlink.hash_email_address("user@example.com")
        assert h1 == h2

    def test_returns_hex_string(self):
        h = chainlink.hash_email_address("test@test.com")
        assert isinstance(h, str)
        assert len(h) == 64
        int(h, 16)  # should not raise


class TestHash:
    """Tests for hash()"""

    def test_deterministic(self):
        h1 = chainlink.hash("hello")
        h2 = chainlink.hash("hello")
        assert h1 == h2

    def test_different_inputs(self):
        h1 = chainlink.hash("hello")
        h2 = chainlink.hash("world")
        assert h1 != h2

    def test_returns_64_char_hex(self):
        h = chainlink.hash("test")
        assert len(h) == 64
        int(h, 16)


class TestHashMessage:
    """Tests for hash_message()"""

    def test_strips_whitespace(self):
        h1 = chainlink.hash_message("hello   world")
        h2 = chainlink.hash_message("hello world")
        assert h1 == h2

    def test_strips_leading_trailing(self):
        h1 = chainlink.hash_message("  hello world  ")
        h2 = chainlink.hash_message("hello world")
        assert h1 == h2

    def test_normalizes_newlines_and_tabs(self):
        h1 = chainlink.hash_message("hello\n\t\tworld")
        h2 = chainlink.hash_message("hello world")
        assert h1 == h2


class TestParseCastSendOutput:
    """Tests for parse_cast_send_output()"""

    SAMPLE_OUTPUT = (
        "blockHash 0xabc123\n"
        "blockNumber 42\n"
        "contract_address \n"
        "cumulativeGasUsed 21000\n"
        "effectiveGasPrice 1000000000\n"
        "gasUsed 21000\n"
        "logs [Log { ... }]\n"
        "logsBloom 0x00\n"
        "root \n"
        "status 1\n"
        "transactionHash 0xdef456\n"
        "transactionIndex 0\n"
        "type 2\n"
    )

    def test_parses_success(self):
        parsed = chainlink.parse_cast_send_output(self.SAMPLE_OUTPUT)
        assert parsed["success"] is True
        assert parsed["blockNumber"] == 42
        assert parsed["transactionHash"] == "0xdef456"

    def test_parses_failure_empty_logs(self):
        output = self.SAMPLE_OUTPUT.replace("[Log { ... }]", "[]")
        parsed = chainlink.parse_cast_send_output(output)
        assert parsed["success"] is False


class TestIsCastAndSendSucceed:
    """Tests for is_cast_and_send_succeed()"""

    def test_success(self):
        output = (
            "blockHash 0xabc\n"
            "blockNumber 1\n"
            "cumulativeGasUsed 1\n"
            "effectiveGasPrice 1\n"
            "gasUsed 1\n"
            "logs [Log]\n"
            "logsBloom 0x\n"
            "root \n"
            "status 1\n"
            "transactionHash 0x1\n"
            "transactionIndex 0\n"
            "type 2\n"
        )
        assert chainlink.is_cast_and_send_succeed(output) is True

    def test_failure(self):
        output = (
            "blockHash 0xabc\n"
            "blockNumber 1\n"
            "cumulativeGasUsed 1\n"
            "effectiveGasPrice 1\n"
            "gasUsed 1\n"
            "logs []\n"
            "logsBloom 0x\n"
            "root \n"
            "status 1\n"
            "transactionHash 0x1\n"
            "transactionIndex 0\n"
            "type 2\n"
        )
        assert chainlink.is_cast_and_send_succeed(output) is False


class TestGetChainmailAddress:
    """Tests for get_chainmail_address()"""

    def test_missing_file(self):
        with patch("os.path.exists", return_value=False):
            assert chainlink.get_chainmail_address() == ""

    def test_exists(self):
        with patch("os.path.exists", return_value=True):
            with patch("builtins.open", mock_open()):
                with patch("yaml.safe_load", return_value={"contract_address": "0xABC"}):
                    assert chainlink.get_chainmail_address() == "0xABC"
