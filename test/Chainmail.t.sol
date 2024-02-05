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

pragma solidity 0.8.20;

import {Chainmail, ChainmailEvents} from "../contracts/Chainmail.sol";
import {Test} from "forge-std/Test.sol";

// solhint-disable var-name-mixedcase

contract ChainmailTest is Test, ChainmailEvents {
    Chainmail private chainmail;
    address private owner = makeAddr("owner");
    address private badOwner = makeAddr("bad owner");
    address private sender = makeAddr("sender");

    // Ownable error
    string errorOwnableUnauthorizedAccount = "OwnableUnauthorizedAccount(address)";

    function setUp() public {
        vm.label(msg.sender, "MSG_SENDER");
        chainmail = new Chainmail();

        // transfer ownership from deployer to owner
        chainmail.transferOwnership(owner);
        vm.startPrank(owner);
        chainmail.acceptOwnership();
        vm.stopPrank();
    }

    function testRegisterEmailAddress(string calldata emailAddress, address emailSender, bytes calldata fingerprint) public {
        bytes32 hashedEmailAddress = keccak256(abi.encode(emailAddress));

        vm.expectEmit(true, true, true, true, address(chainmail));
        emit RegisterEmailAddress(hashedEmailAddress, emailSender, fingerprint);
        vm.startPrank(owner);
        chainmail.registerEmailAddress(hashedEmailAddress, emailSender, fingerprint);
        vm.stopPrank();
    }

    function testRegisterEmailAddressBadOwner(string calldata emailAddress, address emailSender, bytes calldata fingerprint) public {
        bytes32 hashedEmailAddress = keccak256(abi.encode(emailAddress));

        vm.expectRevert(abi.encodeWithSignature(errorOwnableUnauthorizedAccount, badOwner));
        vm.startPrank(badOwner);
        chainmail.registerEmailAddress(hashedEmailAddress, emailSender, fingerprint);
        vm.stopPrank();
    }


    function testEmailAddressInfo(string calldata emailAddress, address emailSender, bytes calldata fingerprint) public {
        bytes32 hashedEmailAddress = keccak256(abi.encode(emailAddress));

        vm.startPrank(owner);
        chainmail.registerEmailAddress(hashedEmailAddress, emailSender, fingerprint);
        vm.stopPrank();

        (address outSender, bytes memory outFingerprint) = chainmail.emailAddressInfo(hashedEmailAddress);
        assertEq(outSender, emailSender);
        assertEq(outFingerprint, fingerprint);
    }

    function testEmailAddressInfoPlaintext(string calldata emailAddress, address emailSender, bytes calldata fingerprint) public {
        bytes32 hashedEmailAddress = keccak256(abi.encode(emailAddress));

        vm.startPrank(owner);
        chainmail.registerEmailAddress(hashedEmailAddress, emailSender, fingerprint);
        vm.stopPrank();

        (address outSender, bytes memory outFingerprint) = chainmail.emailAddressInfoPlaintext(emailAddress);
        assertEq(outSender, emailSender);
        assertEq(outFingerprint, fingerprint);
    }

    function testRegisterEmailMessage(string calldata emailMessage) public {
        bytes32 hashedMessage = keccak256(abi.encode(emailMessage));

        vm.expectEmit(true, true, false, false, address(chainmail));
        emit RegisterMessage(sender, hashedMessage);
        vm.startPrank(sender);
        chainmail.registerEmailMessage(hashedMessage);
        vm.stopPrank();
    }


    function testVerifyEmailMessage(string calldata emailAddress, bytes calldata fingerprint, string calldata emailMessage) public {
        bytes32 hashedEmailAddress = keccak256(abi.encode(emailAddress));
        bytes32 hashedMessage = keccak256(abi.encode(emailMessage));

        vm.startPrank(owner);
        chainmail.registerEmailAddress(hashedEmailAddress, sender, fingerprint);
        vm.stopPrank();

        vm.startPrank(sender);
        chainmail.registerEmailMessage(hashedMessage);
        vm.stopPrank();

        bool ok = chainmail.verifyEmailMessage(hashedEmailAddress, hashedMessage);
        assertTrue(ok);
    }

    function testVerifyEmailMessagePlaintext(string calldata emailAddress, bytes calldata fingerprint, string calldata emailMessage) public {
        bytes32 hashedEmailAddress = keccak256(abi.encode(emailAddress));
        bytes32 hashedMessage = keccak256(abi.encode(emailMessage));

        vm.startPrank(owner);
        chainmail.registerEmailAddress(hashedEmailAddress, sender, fingerprint);
        vm.stopPrank();

        vm.startPrank(sender);
        chainmail.registerEmailMessage(hashedMessage);
        vm.stopPrank();

        bool ok = chainmail.verifyEmailMessagePlaintext(emailAddress, emailMessage);
        assertTrue(ok);
    }

    function testVerifyBadEmailMessage(string calldata emailAddress, bytes calldata fingerprint) public {
        string memory emailMessage = "This is a known message";
        bytes32 hashedEmailAddress = keccak256(abi.encode(emailAddress));
        bytes32 hashedMessage = keccak256(abi.encode(emailMessage));

        vm.startPrank(owner);
        chainmail.registerEmailAddress(hashedEmailAddress, sender, fingerprint);
        vm.stopPrank();

        vm.startPrank(sender);
        chainmail.registerEmailMessage(hashedMessage);
        vm.stopPrank();

        string memory badMessage = "This message has not been registered";
        bytes32 hashedBadMessage = keccak256(abi.encode(badMessage));
        bool notOk = chainmail.verifyEmailMessage(hashedEmailAddress, hashedBadMessage);
        assertFalse(notOk);
    }

    function testVerifyBadEmailAddress(bytes calldata fingerprint, string calldata emailMessage) public {
        string memory emailAddress = "known@domain.com";
        bytes32 hashedEmailAddress = keccak256(abi.encode(emailAddress));
        bytes32 hashedMessage = keccak256(abi.encode(emailMessage));

        vm.startPrank(owner);
        chainmail.registerEmailAddress(hashedEmailAddress, sender, fingerprint);
        vm.stopPrank();

        vm.startPrank(sender);
        chainmail.registerEmailMessage(hashedMessage);
        vm.stopPrank();

        string memory badEmailAddress = "unknown@nowhere.com";
        bytes32 hashedBadAddress = keccak256(abi.encode(badEmailAddress));
        bool notOk = chainmail.verifyEmailMessage(hashedBadAddress, hashedMessage);
        assertFalse(notOk);
    }
}
