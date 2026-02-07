# Copyright (c) 2024, Circle Internet Financial, LTD. All rights reserved.
#
#  SPDX-License-Identifier: Apache-2.0

"""Unit tests for chainmail.py"""

import base64
import sys
import zlib
from unittest.mock import MagicMock, patch

import pytest

# Mock gnupg and config before importing chainmail
mock_gpg_instance = MagicMock()
mock_gnupg = MagicMock()
mock_gnupg.GPG.return_value = mock_gpg_instance
sys.modules["gnupg"] = mock_gnupg

CONFIG = {
    "pgp": {"bin": "/usr/bin/gpg"},
    "chainmail": {"hostname": "https://chainmail.example.com"},
}

with patch("builtins.open", MagicMock()):
    with patch("yaml.safe_load", return_value=CONFIG):
        import chainmail


class TestGetContentString:
    """Tests for get_content_string()"""

    def test_valid_roundtrip(self):
        original = "Hello, this is a PGP signed message."
        compressed = zlib.compress(original.encode("utf-8"))
        encoded = base64.b64encode(compressed).decode("utf-8")
        assert chainmail.get_content_string(encoded) == original

    def test_unicode_content(self):
        original = "Héllo wörld 🌍"
        compressed = zlib.compress(original.encode("utf-8"))
        encoded = base64.b64encode(compressed).decode("utf-8")
        assert chainmail.get_content_string(encoded) == original

    def test_empty_string(self):
        original = ""
        compressed = zlib.compress(original.encode("utf-8"))
        encoded = base64.b64encode(compressed).decode("utf-8")
        assert chainmail.get_content_string(encoded) == original

    def test_invalid_base64_returns_error(self):
        assert chainmail.get_content_string("not-valid-base64!!!") == "FAILED TO PARSE CONTENT"

    def test_invalid_zlib_returns_error(self):
        # Valid base64 but not valid zlib
        encoded = base64.b64encode(b"not compressed data").decode("utf-8")
        assert chainmail.get_content_string(encoded) == "FAILED TO PARSE CONTENT"


class TestGetVerificationUrl:
    """Tests for get_verification_url()"""

    def test_returns_url_with_hostname(self):
        content = "test message"
        url = chainmail.get_verification_url(content)
        assert url.startswith("https://chainmail.example.com/verify?")

    def test_url_contains_encoded_content_param(self):
        content = "test message"
        url = chainmail.get_verification_url(content)
        assert "encoded_content=" in url

    def test_roundtrip_with_get_content_string(self):
        """Verify that get_verification_url and get_content_string are inverses."""
        original = "This is a signed PGP message with special chars: <>&"
        url = chainmail.get_verification_url(original)
        # Extract encoded_content param
        from urllib.parse import parse_qs, urlparse

        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        encoded_content = params["encoded_content"][0]
        assert chainmail.get_content_string(encoded_content) == original


class TestModifySignatureHeader:
    """Tests for modify_signature_header()"""

    def test_replaces_header(self):
        content = "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nHello"
        old = "Hash: SHA256"
        new = "Hash: SHA256\nComment: Verified by Chainmail"
        result = chainmail.modify_signature_header(content, old, new)
        assert "Comment: Verified by Chainmail" in result
        assert result.count("Hash: SHA256") == 1  # old replaced, new present

    def test_no_match_returns_unchanged(self):
        content = "some content"
        result = chainmail.modify_signature_header(content, "not found", "replacement")
        assert result == content

    def test_replaces_only_first_occurrence(self):
        # str.replace replaces all occurrences
        content = "AAA BBB AAA"
        result = chainmail.modify_signature_header(content, "AAA", "CCC")
        assert result == "CCC BBB CCC"


class TestPGPSignMessage:
    """Tests for PGP_sign_message() with mocked GPG"""

    def test_calls_gpg_sign(self):
        mock_sign = MagicMock(return_value=MagicMock(__str__=lambda self: "signed-output"))
        with patch.object(chainmail, "GPG") as mock_gpg:
            mock_gpg.sign = mock_sign
            result = chainmail.PGP_sign_message("data", "FINGERPRINT", "passphrase")
            mock_sign.assert_called_with(
                "data", keyid="FINGERPRINT", passphrase="passphrase", clearsign=True
            )
            assert result == "signed-output"


class TestVerifySignature:
    """Tests for verify_signature() with mocked GPG"""

    def test_calls_gpg_verify(self):
        with patch.object(chainmail, "GPG") as mock_gpg:
            mock_gpg.verify.return_value = True
            result = chainmail.verify_signature("signed data")
            mock_gpg.verify.assert_called_with("signed data")
            assert result is True


class TestEmailSendMessage:
    """Tests for email_send_message()"""

    def test_returns_true(self):
        assert chainmail.email_send_message(
            email_to="a@b.com",
            email_from="c@d.com",
            email_subject="test",
            email_body="body",
            cc_sender=False,
        ) is True


class TestSendEmail:
    """Tests for send_email() integration"""

    def test_send_email_returns_modified_content(self):
        signed_text = "-----BEGIN PGP SIGNATURE-----\nSigned body with $FINGERPRINT note"
        chainmail.GPG = MagicMock()
        chainmail.GPG.sign.return_value = MagicMock(__str__=lambda self: signed_text)
        result = chainmail.send_email(
            email_to="to@example.com",
            email_from="from@example.com",
            email_subject="Subject",
            email_body="Hello",
            cc_sender=False,
            fingerprint="ABC123",
            passphrase="pass",
            fingerprint_note="\nFingerprint: $FINGERPRINT",
            pgp_signature_start="-----BEGIN PGP SIGNATURE-----",
            new_pgp_signature_start="-----BEGIN PGP SIGNATURE-----\nVersion: Chainmail",
        )
        assert "Verify:" in result
        assert "Version: Chainmail" in result
