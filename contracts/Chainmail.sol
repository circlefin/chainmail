// Copyright (c) 2024, Circle Internet Financial, LTD. All rights reserved.
//
//  SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

pragma solidity ^0.8.20;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";


contract ChainmailEvents {
    event RegisterEmailAddress(
        bytes32 indexed hashedEmailAddress,
        address indexed sender,
        bytes fingerprint
    );

    event RegisterMessage(
        address indexed sender,
        bytes32 indexed hashedMessage
    );
}

contract Chainmail is ChainmailEvents, Ownable2Step {
    // registeredMessage[sender][hashed_email_message] = true | false
    mapping(address => mapping(bytes32 => bool)) public registeredMessage;

    // registeredSender[hashed_email_address] = sender
    mapping(bytes32 => address) public registeredSender;

    // registeredFingerprint[hashed_email_address] = fingerprint
    mapping(bytes32 => bytes) public registeredFingerprint;

    constructor() Ownable(msg.sender) { }

    function registerEmailAddress(bytes32 hashedEmailAddress, address sender, bytes calldata fingerprint) onlyOwner public {
        registeredSender[hashedEmailAddress] = sender;
        registeredFingerprint[hashedEmailAddress] = fingerprint;
        emit RegisterEmailAddress(hashedEmailAddress, sender, fingerprint);
    }

    function registerEmailMessage(bytes32 hashedEmailMessage) public {
        registeredMessage[msg.sender][hashedEmailMessage] = true;
        emit RegisterMessage(msg.sender, hashedEmailMessage);
    }

    function emailAddressInfo(bytes32 hashedEmailAddress) public view returns(address, bytes memory) {
        address sender = registeredSender[hashedEmailAddress];
        bytes memory fingerprint = registeredFingerprint[hashedEmailAddress];
        return (sender, fingerprint);
    }

    function emailAddressInfoPlaintext(string calldata emailAddress) public view returns(address, bytes memory) {
        bytes32 hashedEmailAddress = keccak256(abi.encode(emailAddress));
        return emailAddressInfo(hashedEmailAddress);
    }

    function verifyEmailMessage(bytes32 hashedEmailAddress, bytes32 hashedEmailMessage) public view returns(bool) {
        address sender = registeredSender[hashedEmailAddress];
        return registeredMessage[sender][hashedEmailMessage];
    }

    function verifyEmailMessagePlaintext(string calldata emailAddress, string calldata emailMessage) public view returns(bool) {
        bytes32 hashedEmailAddress = keccak256(abi.encode(emailAddress));
        bytes32 hashedEmailMessage = keccak256(abi.encode(emailMessage));
        return verifyEmailMessage(hashedEmailAddress, hashedEmailMessage);
    }
}


