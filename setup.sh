#!/bin/sh

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

# update submodules
git submodule update --init --recursive

# Install GPG
pip3 install python-gnupg
export GPG_TTY=$(tty)

# Install ncecesary packages
pip3 install --upgrade google-api-python-client google-auth-httplib2 google-auth-oauthlib
pip install pyyaml
pip install flask
pip install web3
pip install requests
