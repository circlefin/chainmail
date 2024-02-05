# Chainmail
Protecting email recipients using the blockchain.

## License
This work is licensed under Apache 2.0. 

`SPDX-License-Identifier: Apache-2.0`

## Setup

### Install GnuPG
Install GPG and GPA https://www.gnupg.org/. 

For Mac:
```
brew install GnuPG
brew install gpa
```

### Install Foundry and Anvil
You will need Foundry to make `cast send` RPC calls to the Ethereum testchain. You
will also need to use anvil if you want to have a local test node.
```
curl -L https://foundry.paradigm.xyz | bash
foundryup
```

### Configure Virtual Environment
To create a virtual environment, execute the following commands
```
# Create virtual environment .venv in local dir
python3 -m venv ./.venv

# start virtual environment
source ./.venv/bin/activate

# Install packages (this will take a few minutes)
source setup
```

To exit the virtual environment
```
deactivate
```

To restart the virtual environment
```
source ./.venv/bin/activate
```

### (Optional) Generate your own PGP key
The project comes with a default PGP key in `test_data/alice_private_key.asc` that will be automatically installed
when you run `register-for-demo.py`. You can generate your own key
using GPG that you installed earlier. Update the `sender` field in `config.yaml` with the email address and
fingerprint associated with the key. Note: PGP format automatically inserts the key's username and email address into
every signature.

### (Optional) Install Mailvelope
Mailvelope can sign emails with PGP and automatically verifies PGP signed messages.

Add Mailvelope to Google Chrome https://chrome.google.com/webstore/detail/mailvelope/kajibbejlbohfaggdiogboambcijhkke

Add a PGP key for signing here: chrome-extension://kajibbejlbohfaggdiogboambcijhkke/app/app.html#/settings/general

When you compose a new email in the browser, a Mailvelope red logo will appear in the corner of the New Email window. Click it to send a secure email.

## Run
Overview of all the steps, with more details provided above/below.

To send emails:
1. Open a fresh terminal window to run the web server. Activate the virtual environment and then run `python runwebsite.py`.
1. Open your browser to `http://localhost:5000`
1. There is a form at the bottom of the page for sending emails. Since this is a demo, no email will actually be sent. 
Instead, the signed email text will appear in the side panel.

To verify emails using an anvil node
1. (Default) Set the configuration file `config.yaml` to point at `test_data/anvil_keys.yaml`.
1. Open a fresh terminal window and run `anvil` without any arguments.
1. Open a separate window and run the script `python register-for-demo.py`. This will deploy a fresh contract and register
the email sender in the `config.yaml` file and the sender address in `test_data/anvil_keys.yaml`.
1. Open a fresh terminal window to start the web server. Activate the virtual environment and then run `python runwebsite.py`.
1. Open your browser to `http://localhost:5000`. You can now enter emails to verify.

To verify emails using the deployed testnet contract
1. Follow the instructions below to connect to Ethereum using an Infura RPC key.
1. Open a fresh terminal window to start the web server. Activate the virtual environment and then run `python runwebsite.py`.
1. Open your browser to `http://localhost:5000`. You can now enter emails to verify.

### To run the webserver 
If you are using anvil as your network, run `anvil` in a separate window. 

Activate your virtual environment and run `python runwebsite.py`

Open a browser window to http://localhost:5000/

Enter the raw text of a message sent by Chainmail into the textarea and click on the `Verify` button.
The send email form signs the email message and displays the result.

### Connect to anvil
You can run a local anvil node to test Chainmail. Make sure that the config file `config.yaml` has the line:
```
local_key_file: './test_data/anvil_keys.yaml'
```
The file `./test_data/anvil_keys.yaml` is configured with
the correct `rpc_url` and an `owner` and `sender` anvil account. These are all default keys that ship with every
anvil.

In a separate window, execute the command `anvil`. This will start a fresh instance of local anvil node.
You will need to deploy a fresh copy of the `Chainmail.sol` contract each time you start `anvil`. The script
`register-for-demo` does this automatically, or you can call `python chainlink.py`.

## Connect to Ethereum using Infura
To connect to Ethereum, you need to create a `local_test_data/keys.yaml` file with
private key information and an RPC URL.

Make a copy of `test_data/anvil_keys.yaml` and rename it something like `local_test_data/keys.yaml`. Configure
`config.yaml` to point to this new file:
```
# config.yaml

local_key_file: './local_test_data/keys.yaml'
```

You will need to do the following to your new key file:
- (Optional) Obtain Ethereum accounts for contract owner and message sender. Set the owner and sender information
  in the `keys.yaml` file using funded accounts. You can skip this step if you don't plan to deploy a contract or register 
  email addresses. Email verificatin does not require funded accounts. 
- Obtain an Infura API key by registering here:  https://app.infura.io/register
- Set your `rpc_url` in the `keys.yaml` file to point at the appropriate network and include an Infura API key. 
The URL will look something like `rpc_url: 'https://goerli.infura.io/v3/<token>'
  `
- Set the contract address in the file `.chainmail_env`. We currently have a contract on the Goerli test network at
`0x1866053Ec573dC3a50EB4A27f3836d867c622D41` that you can 
view at https://goerli.etherscan.io/address/0x1866053ec573dc3a50eb4a27f3836d867c622d41

```
# .chainmail_env

contract_address: '0x1866053Ec573dC3a50EB4A27f3836d867c622D41'
```

### Command Line Interface
The `chainlink.py` script interacts with an Ethereum network. Use the configuration file `config.yaml` to configure your
connection to use anvil, testnet, or mainnet.

Run `python chainlink.py` to get the exact usage instructions. You can
- Deploy an instance of the Chainmail contract.
- Register an email address, fingerprint, and sender Ethereum address.
- Register an email message.
- Verify a fingerprint corresponds to an email address.
- Verify an email message has been registered.

There is a script `python register-for-demo.py` that will automatically deploy a contract, register the email sender in
`config.yaml` and the email in `test_data/good_sent_email.asc`.

### Test Files
The directory `test_data` has some test email messages. You can use them as test data on the command
line with `python chainlink.py` or copy+paste into the web browser for verification.
- `good_sent_email.asc`. This email is signed using the default PGP fingerprint and the script `register-for-demo.py` will
register both the PGP fingerprint and the contents of the email.
- `ok_sent_email.asc`. This email has a valid PGP signature and `register-for-demo.py` will register the signer PGP key.
However, the text of the message is not registered.
- `unregistered_signed_email.asc`. This email has a valid PGP signature, however the PGP fingerprint is not registered.
- `bad_sent_email.asc`. This email has an invalid PGP signature.

### Generate mainnet/testnet address ###
You need an Ethereum  address with ETH to register keys. The following command line command will generate an Ethereum account and private key
```
python3 -c "from web3 import Web3; w3 = Web3(); acc = w3.eth.account.create(); print(f'private key={w3.to_hex(acc._private_key)}, account={acc.address}')"
```

Store the information in `local_test_data/keys.yaml` in the format:
```
testnet_account:
  private key: # private key goes here
  address: 0x4a7b50811D0ADbE2A1AB6218eA4a5EC0a47c9DCb
```
