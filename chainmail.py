# Copyright (c) 2024, Circle Internet Financial, LTD. All rights reserved.
#
#  SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import base64
import binascii
import gnupg
import urllib
import yaml
import zlib

CONFIG_FILE = 'config.yaml'
with open(CONFIG_FILE, 'r', encoding='utf-8') as _config_handle:
    CONFIG = yaml.safe_load(_config_handle)

GPG = gnupg.GPG(CONFIG['pgp']['bin'])
GPG.encoding = 'utf-8'


"""
This is the main function for sending emails. It performs the following:
1. It adds a fingerprint note to the email_body.
2. Signs the new email_body.
3. Modifies the signature header to include Mailvelope version info.
4. Modifies the signature header to include a verification link.
5. Calls a (dummy) function to actually send the email using an SMTP provider.
The function returns a string with the text of the PGP signed message.
"""
def send_email(email_to, email_from, email_subject, email_body, cc_sender, fingerprint, passphrase, fingerprint_note, pgp_signature_start, new_pgp_signature_start):
    fingerprint_note = fingerprint_note.replace("$FINGERPRINT", fingerprint)
    content = email_body + fingerprint_note
    content = PGP_sign_message(content, fingerprint, passphrase)
    verification_url = get_verification_url(content)
    new_pgp_signature_start = new_pgp_signature_start + '\nVerify: ' + verification_url + '\n'
    content = modify_signature_header(content, pgp_signature_start, new_pgp_signature_start)
    email_send_message(
        email_to = email_to,
        email_from = email_from,
        email_subject = email_subject,
        email_body = content,
        cc_sender = cc_sender)

    return content

# Sending an email requires connecting to an SMTP server. Users can insert custom
# code here if they want Chainmail to actually send PGP signed email messages. By default,
# Chainmail will simply display the PGP signed email on the webpage in runwebsite.py
def email_send_message(email_to, email_from, email_subject, email_body, cc_sender):
    # Insert SMTP provider code here
    return True

# Given a PGP signed email message content, generate a verification URL that directs the user
# to the Chainmail verification page displayed by runwebsite.py.
def get_verification_url(content):
    compressed_content = zlib.compress(content.encode('utf8'))
    encoded_content = base64.b64encode(compressed_content)
    url_safe_content = encoded_content.decode('utf8')
    base_url = CONFIG['chainmail']['hostname']
    params = { 'encoded_content' : url_safe_content }
    url = base_url + "/verify?" + urllib.parse.urlencode(params)
    return url


# Upper bound on the inflated size of a verification payload. The compressed
# content arrives in a URL query parameter, i.e. from an untrusted caller, and a
# few hundred bytes of zlib can expand to gigabytes ("decompression bomb"), which
# is a single-request memory exhaustion of the web process.
MAX_DECOMPRESSED_BYTES = 1 * 1024 * 1024

# Bound on the base64 input itself, so an oversized request is rejected before
# any decoding work happens.
MAX_ENCODED_BYTES = 256 * 1024


def get_content_string(base64_content):
    if base64_content is None or len(base64_content) > MAX_ENCODED_BYTES:
        return "FAILED TO PARSE CONTENT"
    try:
        # `validate=True` rejects non-alphabet characters instead of silently
        # discarding them.
        decoded = base64.b64decode(base64_content, validate=True)
        decompressor = zlib.decompressobj()
        # Inflate at most MAX_DECOMPRESSED_BYTES + 1 so an overlong payload can be
        # detected without ever materialising it in full.
        decompressed = decompressor.decompress(decoded, MAX_DECOMPRESSED_BYTES + 1)
        if len(decompressed) > MAX_DECOMPRESSED_BYTES:
            return "FAILED TO PARSE CONTENT"
        content = decompressed.decode('utf-8')
    except (binascii.Error, ValueError, zlib.error, UnicodeDecodeError):
        # Specific exceptions only: a bare `except` also swallowed
        # KeyboardInterrupt, SystemExit, and genuine programming errors.
        return "FAILED TO PARSE CONTENT"
    else:
        return content


def PGP_encrypt_message():
    return "hello world"


def PGP_sign_message(data, fingerprint, passphrase):
    print(f'Signing with fingerprint {fingerprint}')
    signed_data = GPG.sign(data, keyid=fingerprint, passphrase=passphrase, clearsign=True)
    return str(signed_data)


def modify_signature_header(content, old_header, new_header):
    return content.replace(old_header, new_header)


def verify_signature(data):
    ok = GPG.verify(data)
    return ok
