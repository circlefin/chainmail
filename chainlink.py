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

USAGE_INSTRUCTIONS = """
# Instructions for calling chainlink.py from the command line. This works with
# both local anvil nodes and testnet/mainnet. The accounts and rpc_url are specified
# in the KEY_FILE. All other configuration is in CONFIG_FILE,

# Deploy the Chainmail contract to the network. Automatically stores contract addresss in ENV_CONFIG_FILE
# where it will be used by other commands.
python chainlink.py deploy

# register an email at the Chainmail contract specified in file ENV_CONFIG_FILE
# will automatically casefold all input so verification is not case-sensitive.
python chainlink.py register-email <user@domain.com> <sender_ethereum_address> <pgp_fingerprint>
python chainlink.py register-email user@testdomain.com 0x70997970C51812dc3A010C7d01b50e0d17dc79C8 4DD9C7CA778A0BCFCF0A4635294DADB0D448AC5E

# register the contents of a file to the sender address in CONFIG_FILE
# uses ENV_CONFIG_FILE to determine the contract address
python chainlink.py register-message-file <filename>

# outputs the keccak hash of the email address (lowercase)
python chainlink.py hash-email <email_address>

# outputs the keccak hash of a file after replacing all whitespace
python chainlink.py hash-file <filename>

# verifies if the fingerprint and email have been registered (not case sensitive)
python chainlink.py verify <fingerprint> <email>

# verifies if the email message has been registered by sender email address
python chainlink.py verify-file <sender_email> <email_filename>
"""

from chainmail import verify_signature
import eth_abi
import os
from Crypto.Hash import keccak
import re
import shlex
import subprocess
import sys
import yaml


def _load_yaml(path):
    """Load a YAML document, closing the file handle deterministically."""
    with open(path, 'r', encoding='utf-8') as handle:
        return yaml.safe_load(handle)


CONFIG_FILE = './config.yaml'
CONFIG = _load_yaml(CONFIG_FILE)
contract_file = CONFIG['chainlink']['contract_file']
fun_register_email_address = CONFIG['chainlink']['register_email_address']
fun_register_email_message = CONFIG['chainlink']['register_email_message']
fun_email_address_info = CONFIG['chainlink']['email_address_info']
fun_verify_email_message = CONFIG['chainlink']['verify_email_message']

KEY_FILE = CONFIG['local_key_file']
KEY = _load_yaml(KEY_FILE)
owner_private_key = KEY['testnet_account']['private_key']
sender_private_key = KEY['testnet_sender']['private_key']
sender_address = KEY['testnet_sender']['address']
rpc_url = KEY['rpc_url']
etherscan_api_key = KEY['etherscan_api_key']

ENV_CONFIG_FILE = CONFIG['chainlink']['local_env_file']

# Values that must never appear in stdout/stderr echoes of a command line.
# Commands are logged for operator visibility, and the previous implementation
# printed them verbatim, which wrote the deployer and sender private keys and the
# Etherscan API key into terminal scrollback, CI logs, and shell history.
_SECRETS = tuple(
    secret
    for secret in (owner_private_key, sender_private_key, etherscan_api_key)
    if isinstance(secret, str) and secret
)


def redact(text):
    """Replace every known secret in ``text`` with a placeholder."""
    if not isinstance(text, str):
        return text
    for secret in _SECRETS:
        text = text.replace(secret, '<redacted>')
    return text


# Saves the state of the local environment to ENV_CONFIG_FILE.
def save_env(chainmail_address):
    env = dict()
    env['contract_address'] = chainmail_address
    # `with` guarantees the file is flushed and closed; the previous version left
    # the handle to the garbage collector, so the address could be missing from
    # the file when a later step read it back.
    with open(ENV_CONFIG_FILE, 'w', encoding='utf-8') as file:
        yaml.dump(env, file)

# Read ENV_CONFIG_FILE to get address of Chainmail contract
def get_chainmail_address():
    if os.path.exists(ENV_CONFIG_FILE):
        env = _load_yaml(ENV_CONFIG_FILE)
        chainmail_address = env['contract_address']
        print(f'Chainmail address: {chainmail_address}')
        return chainmail_address
    else:
        print("Cannot get chainmail_address")
        return ''


def _run(argv):
    """Run ``argv`` without a shell and return (exit_code, stdout+stderr).

    The command is passed as an argument vector, so values interpolated into it
    (email addresses, file contents, contract addresses, fingerprints) can no
    longer terminate the command and start another one — which was possible while
    these commands were built as f-strings and handed to ``os.popen``.
    """
    print(redact(' '.join(shlex.quote(arg) for arg in argv)))
    completed = subprocess.run(
        argv,
        capture_output=True,
        text=True,
        check=False,
    )
    output = (completed.stdout + completed.stderr).strip()
    print(redact(output))
    return completed.returncode, output


# Executes the command and returns the output.
# Kills the current process on failure.
def execute_or_die(argv):
    # The process exit status is authoritative. Previously failure was inferred
    # from the substring "error" in stdout, which both missed silent failures and
    # aborted on success when a payload happened to contain that word.
    returncode, output = _run(argv)
    if returncode != 0:
        print(f'exit(1): command failed with exit status {returncode}')
        exit(1)
    return output

# Executes the command and returns the output.
def execute(argv):
    _, output = _run(argv)
    return output

# Returns a dictionary object of the output of `cast send`
def parse_cast_send_output(output):
    keys = {'blockHash': 'string', # 0xhex
            'blockNumber': 'int',
            'contract_address': 'string', # 0xhex or blank
            'cumulativeGasUsed': 'int',
            'effectiveGasPrice': 'int',
            'gasUsed': 'int',
            'logs': 'string',
            'logsBloom': 'string',
            'root': 'string', # empty string on anvil
            'status': 'int',
            'transactionHash': 'string', # 0xhex
            'transactionIndex': 'int',
            'type': 'int'}
    parsed = {}
    for key, format in keys.items():
        # Raw string: `\s` is not a valid escape in a regular string literal and
        # is a DeprecationWarning that becomes a SyntaxError in future Pythons.
        found = re.findall(rf'{re.escape(key)}\s(.+?)\n', output)
        if len(found) > 0:
            value = found[0].strip()
            if format == 'int':
                parsed[key] = int(value, 10)
            else:
                parsed[key] = found[0].strip()

    # Use logs to check for success/failure. `.get` because a truncated or error
    # response has no `logs` line at all, which previously raised KeyError instead
    # of reporting the call as unsuccessful.
    parsed['success'] = parsed.get('logs', '[]') != '[]'

    return parsed

# The shell command `cast send` returns string output that needs to be parsed to determine if the call succeeded.
# Sample usage:
#   command = f'cast send {arguments}'
#   output = execute_or_die(command)
#   if is_cast_and_send_succeed(output):
#       foo()
#   else:
#       bar()
# Returns True or False depending on string output
def is_cast_and_send_succeed(output):
    parsed = parse_cast_send_output(output)
    return parsed['success']

# Returns a hash of the input string using the Ethereum hash function keccak256
def hash(input):
    input_bytes = eth_abi.encode(['string'], [input])
    keccak_hash = keccak.new(digest_bits=256)
    keccak_hash.update(input_bytes)
    hash = keccak_hash.hexdigest()
    print(f'keccak-256: {hash}')
    return hash

# Strips whitespace and replaces with single ' ' prior to hashing
def hash_message(input):
    input = input.strip()
    input = ' '.join(input.split())
    return hash(input)

# Returns a keccak hash of the email address using Ethereum hash function.
# The email address is hashed in casefold() to ensure consistency with future
# verification queries.
def hash_email_address(email):
    input = email.casefold()
    return hash(input)

# Executes the `forge create` shell command to deploy the contract. The address is
# saved locally in a file for future use.
def deploy():
    # deploy smart contract
    command = [
        'forge', 'create', f'{contract_file}:Chainmail',
        '--private-key', owner_private_key,
        '--rpc-url', rpc_url,
    ]
    if etherscan_api_key != '':
        command += ['--etherscan-api-key', etherscan_api_key, '--verify']
    output = execute_or_die(command)

    # Save address of smart contract in environment for future use. This is important for testing on local anvil
    # node because the contract address can change with each test run.
    found = re.findall(r'Deployed to:\s(.*)\s+Transaction', output)
    if len(found) == 0:
        print(f'You must manually set the environment file .chainmail_env to the contract address.')
        exit(0)
    chainmail_address = found[0]
    save_env(chainmail_address)
    print()
    print(f'Successfully deployed contract Chainmail to {chainmail_address}.')

# Registers an email address to the deployed Chainmail contract. Uses the owner in the KEY_FILE
# and the contract address in ENV_CONFIG_FILE when calling cast send.
def register_email(email, sender, fingerprint):
    hashed_email = hash_email_address(email)
    chainmail_address = get_chainmail_address()
    command = [
        'cast', 'send',
        '--private-key', owner_private_key,
        '--rpc-url', rpc_url,
        chainmail_address,
        fun_register_email_address,
        hashed_email, sender, fingerprint,
    ]
    output = execute_or_die(command)
    if is_cast_and_send_succeed(output):
        print(f'Success: registered {email} as {hashed_email} {sender} {fingerprint}')
    else:
        print(f'Fail: could not register {email} as {hashed_email} {sender} {fingerprint}')

# Registers an email message to the deployed Chainmail contract. Uses the sender in the KEY_FILE
# and the contract address in ENV_CONFIG_FILE when calling cast send.
def register_email_message(message):
    hashed_message = hash_message(message)
    chainmail_address = get_chainmail_address()
    command = [
        'cast', 'send',
        '--private-key', sender_private_key,
        '--rpc-url', rpc_url,
        chainmail_address,
        fun_register_email_message,
        hashed_message,
    ]
    output = execute_or_die(command)
    result = parse_cast_send_output(output)
    if result['success']:
        print(f'Sucessfully registered message {hashed_message} from sender {sender_address}')
    else:
        print(f'Fail: could not register message {hashed_message} from sender {sender_address}')


# Registers an email message to the deployed Chainmail contract. Uses the sender in the KEY_FILE
# and the contract address in ENV_CONFIG_FILE when calling cast send.
def register_email_message_file(filename):
    with open(filename, 'r', encoding='utf-8') as file:
        message = file.read()
    register_email_message(message)

# Verifies the fingerprint and email have been registered.
# Uses the contract address in ENV_CONFIG_FILE when calling cast call.
def verify_fingerprint_and_email(fingerprint, email):
    hashed_email = hash_email_address(email)
    chainmail_address = get_chainmail_address()
    command = [
        'cast', 'call', chainmail_address,
        '--rpc-url', rpc_url,
        fun_email_address_info,
        hashed_email,
    ]
    output = execute(command)

    # cast call returns blank output on Error (e.g. wrong contract address)
    if output is None or output == '' or output.isspace():
        print(f'Fail: email {email} not registered')
        return False

    # output of cast call should be two rows of text with sender address and fingerprint
    results = output.split("\n")
    if len(results) != 2:
        print(f'Fail: could not process blockchain output, assuming email {email} not registered.')
        return False

    # returned fingerprint will be 0x if it is not registered
    if len(results[1].strip()) <= 2:
        print(f'Fail: no fingerprint is registered for {email}.')
        return False

    # compare registered fingerprint to function argument
    registered_fingerprint = results[1].strip().casefold()[2:]
    if registered_fingerprint != fingerprint.casefold():
        print(f'Fail: {email} registered fingerprint {registered_fingerprint} does not match query {fingerprint}.')
        return False

    print(f'Success: verified registration for {email} {fingerprint}.')
    return True

# Verifies the email message has been registered.
# Uses the contract address in ENV_CONFIG_FILE when calling cast call.
def verify_email_message(sender_email, message):
    hashed_email = hash_email_address(sender_email)
    hashed_message = hash_message(message)
    chainmail_address = get_chainmail_address()
    command = [
        'cast', 'call', chainmail_address,
        '--rpc-url', rpc_url,
        fun_verify_email_message,
        hashed_email, hashed_message,
    ]
    returncode, output = _run(command)

    # Fail closed. The previous logic returned True for anything that did not
    # contain the substring "false", so an RPC error, an empty response, a wrong
    # contract address, or a missing `cast` binary all reported the message as
    # verified. Only an explicit affirmative answer counts as verification.
    if returncode != 0:
        print('Fail: verification call did not complete successfully.')
        return False

    answer = output.strip().casefold()
    # `cast call` renders a bool return value as "true"/"false", and an ABI-encoded
    # word as 0x00..01 / 0x00..00 depending on the cast version.
    if answer == 'true' or (answer.startswith('0x') and set(answer[2:]) <= set('0123456789abcdef') and int(answer, 16) == 1):
        return True

    if answer != 'false' and int_or_none(answer) != 0:
        print(f'Fail: unrecognised verification response; treating as not verified.')
    return False


def int_or_none(text):
    """Best-effort integer parse used only to classify a hex/decimal response."""
    try:
        return int(text, 0)
    except (TypeError, ValueError):
        return None

# Verifies the email message in the file has been registered.
# Uses the contract address in ENV_CONFIG_FILE when calling cast call.
def verify_email_message_file(sender_email, filename):
    with open(filename, 'r', encoding='utf-8') as file:
        message = file.read()
    return verify_email_message(sender_email, message.strip())


# Processes command line arguments
if __name__ == '__main__':
    arglen = len(sys.argv)
    if arglen > 1 and sys.argv[1] == 'deploy':
        deploy()
    elif arglen > 4 and sys.argv[1] == 'register-email':
        register_email(sys.argv[2], sys.argv[3], sys.argv[4])
    elif arglen > 2 and sys.argv[1] == 'register-message-file':
        register_email_message_file(sys.argv[2])
    elif arglen > 2 and sys.argv[1] == 'hash-email':
        hash_email_address(sys.argv[2])
    elif arglen > 2 and sys.argv[1] == 'hash-file':
        with open(sys.argv[2], 'r', encoding='utf-8') as file:
            message = file.read()
        hash_message(message)
    elif arglen > 3 and sys.argv[1] == 'verify':
        verify_fingerprint_and_email(fingerprint=sys.argv[2], email=sys.argv[3])
    elif arglen > 3 and sys.argv[1] == 'verify-file':
        verify_email_message_file(sys.argv[2], sys.argv[3])
    else:
        print(USAGE_INSTRUCTIONS)
        exit(0)