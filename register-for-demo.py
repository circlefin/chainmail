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

# Usage: this script does not require any arguments. It uses the defaults in the configuration files.
# If using anvil, make sure the KEY_FILE points at anvil and run anvil in a separate window.
# If using testnet, configure the KEY_FILE to point at testnet.
#
# To run the script:
# python register-for-demo.py
#
# The script will deploy new Chainmail smart-contract to the blockchain, register an email address and an email message.
# The script will verify the registration and output "Success" if all goes well.

from chainlink import deploy, register_email, verify_fingerprint_and_email, register_email_message_file, verify_email_message_file
from runwebsite import check_email_message_file
import gnupg
import yaml

CONFIG_FILE = './config.yaml'
CONFIG = yaml.safe_load(open(CONFIG_FILE, 'r'))
email = CONFIG['sender']['email']
fingerprint = CONFIG['sender']['fingerprint']
test_pgp_private_key_file = CONFIG['chainmail']['test_pgp_private_key_file']
test_pgp_fingerprint = CONFIG['chainmail']['test_pgp_fingerprint']
test_pgp_private_key_passphrase = CONFIG['chainmail']['test_pgp_private_key_passphrase']

KEY_FILE = CONFIG['local_key_file']
KEY = yaml.safe_load(open(KEY_FILE, 'r'))
sender_address = KEY['testnet_sender']['address']

test_message_filename = './test_data/good_sent_email.asc'

# import test PGP private key file
gpg = gnupg.GPG('/usr/local/bin/gpg')
gpg.encoding = 'utf-8'
gpg.delete_keys(fingerprints=test_pgp_fingerprint, passphrase=test_pgp_private_key_passphrase, secret=True)
gpg.delete_keys(fingerprints=test_pgp_fingerprint, passphrase=test_pgp_private_key_passphrase, secret=False)
import_result = gpg.import_keys_file(test_pgp_private_key_file)
gpg.trust_keys(fingerprint, 'TRUST_ULTIMATE')
print(f'Import PGP key: {import_result}')

# deploy Chainmail.sol
deploy()

# register email and fingerprint on Chainmail.sol
register_email(email, sender_address, fingerprint)

# register an email on Chainmail.sol
register_email_message_file(test_message_filename)

# verify registration
verify_fingerprint_and_email(fingerprint, email)
check = check_email_message_file(test_message_filename)
verified = check['verified']
details = check['details']
print(f'Verify file {test_message_filename}: {verified}')
print(f'{details}')
ok = verify_email_message_file(email, test_message_filename)


