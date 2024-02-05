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
# If using anvil, make sure the KEY_FILE points at anvil, run register-for-demo.py to deploy a test contract,
# and run anvil in a separate window.
# If using testnet, configure the KEY_FILE to point at testnet.
#
# To run the script:
# python runwebsite.py
#
# The script will start a Flask webserver to run the website. The default address is in the CONFIG file.


from chainmail import send_email, get_content_string, verify_signature
from chainlink import verify_fingerprint_and_email, verify_email_message
from flask import Flask, request, render_template

import gnupg
import re
import yaml

app = Flask(__name__)

CONFIG_FILE = 'config.yaml'
CONFIG = yaml.safe_load(open(CONFIG_FILE, 'r'))

# Displays the homepage in home.html
@app.route('/')
def home():
    return render_template('home.html', verified='NONE')

# Signs an email message, then displays it on the homepage home.html.
# See chainlink.py for instructions to enable sending the email.
@app.route('/send', methods=['POST', 'GET'])
def send():
    form_request = request.form
    if 'message' not in form_request:
        return render_template('home.html', verified='NONE')
    elif 'email_to' not in form_request:
        return render_template('home.html', verified='NONE')
    elif 'subject' not in form_request:
        return render_template('home.html', verified='NONE')

    content = send_email(
        email_to = form_request['email_to'], 
        email_from = CONFIG['sender']['email'],
        email_subject = form_request['subject'], 
        email_body = form_request['message'], 
        cc_sender= CONFIG['chainmail']['cc_sender'],
        fingerprint=CONFIG['sender']['fingerprint'], 
        passphrase = CONFIG['sender']['passphrase'], 
        fingerprint_note = CONFIG['pgp']['fingerprint_note'],
        pgp_signature_start = CONFIG['pgp']['pgp_signature_start'],
        new_pgp_signature_start = CONFIG['pgp']['new_pgp_signature_start'])

    return render_template(
        'home.html', 
        verified='NONE',
        email_sent='True',
        email_to = form_request['email_to'], 
        email_from = CONFIG['sender']['email'],
        email_subject = form_request['subject'], 
        email_body = content, 
        cc_sender= CONFIG['chainmail']['cc_sender'],
        fingerprint=CONFIG['sender']['fingerprint']
        )

# Verifies a PGP signed message:
# 1. Checks the PGP signature.
# 2. Check if the message is registered to the Chainmail smart contract.
# 3. Extracts sender email address from PGP signature and checks if it is is registered to the Chainmail smart contract
# Returns a dictionary object with the results of these checks.
def check_message(message):
    check = dict()
    valid = verify_signature(message)
    if valid:
        print("valid")
        check['valid'] = True
        check['fingerprint'] = valid.fingerprint
        check['username'] = valid.username
        check['creation_date'] = valid.creation_date

        # sender_email can be in format 'user@domain.com' or 'My Full Name <user@domain.com>'
        found_email = re.findall('\<.+\>', valid.username.strip())
        if len(found_email) > 0:
            sender_email = found_email[0][1:-1]
        else:
            sender_email = valid.username.strip()

        # check if (fingerprint, email) registered with blockchain
        if verify_fingerprint_and_email(valid.fingerprint, sender_email):
            check['verified'] = 'OK'
            check['details'] = f'Signature is valid and username {sender_email} is registered with Ethereum to use this public key.'
        else:
            check['verified'] = 'UNREGISTERED'
            check['details'] = f'The signature is valid, but username {sender_email} not registered with Ethereum to use this public key.'

        # check if sender_email has registered the message with blockchain
        if verify_email_message(sender_email, message):
            check['registered_message'] = True
            check['details'] = check['details'] + ' The email sender has registered the message with Ethereum.'
        else:
            check['registered_message'] = False
            check['details'] = check['details'] + ' The email sender has NOT registered the message with Ethereum.'

    else:
        print("invalid")
        check['valid'] = False
        check['verified'] = 'FAIL'
        check['registered_message'] = False
        check['details'] = valid.problems

    print(check)
    return check

# Checks a PGP signed email message stored in the file.
# See function check_email_message() above
def check_email_message_file(filename):
    file = open(filename, 'r')
    message = file.read()
    return check_message(message.strip())

# Verifies the PGP signed email message. The input can come either from
# the form defined in home.html or the verification URL generated by chainmail.py.
@app.route('/verify', methods=['POST', 'GET'])
def verify():
    form_request = request.form
    if 'raw_text' in form_request:
        message = form_request['raw_text']
        if not message:
            return render_template('home.html', verified='NONE')
    else:
        encoded_content = request.args.get('encoded_content')
        if not encoded_content:
            return render_template('home.html', verified='NONE')
        message = get_content_string(encoded_content)

    check = check_message(message.strip())
    if check['valid']:
        return render_template(
            'home.html', 
            msg=message, 
            verified=check['verified'],
            fingerprint=check['fingerprint'],
            username=check['username'],
            creation_date=check['creation_date'],
            details=check['details'],
            registered_message=check['registered_message'])
    else:
       return render_template(
            'home.html', 
            msg=message,
            verified=check['verified'],
            problems=check['details'])

# Run the Flask webserver
if __name__ == '__main__':
    app.run(debug=True)


