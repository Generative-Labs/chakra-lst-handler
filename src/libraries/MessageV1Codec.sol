// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {Message, PayloadType} from "./Message.sol";

library MessageV1Codec {
    uint8 internal constant MESSAGE_VERSION = 1;

    // header (version + id +  type)
    // version
    uint256 internal constant PACKET_VERSION_OFFSET = 0;
    // id
    uint256 internal constant ID_OFFSET = 1;
    // type
    uint256 internal constant PAYLOAD_TYPE_OFFSET = 33;
    // payload
    uint256 internal constant PAYLOAD_OFFSET = 34;

    function encode(Message memory _msg) internal pure returns (bytes memory encodedMessage) {
        encodedMessage = abi.encodePacked(MESSAGE_VERSION, _msg.id, _msg.payload_type, _msg.payload);
    }

    function payload(bytes calldata _msg) internal pure returns (bytes calldata) {
        return bytes(_msg[PAYLOAD_OFFSET:]);
    }

    function payload_hash(bytes calldata _msg) internal pure returns (bytes32) {
        return keccak256(payload(_msg));
    }

    function address_from_u256(uint256 value) external pure returns (address) {
        require(value <= type(uint160).max, "Value exceeds address range");
        return address(uint160(value));
    }

    function u256_from_address(address value) external pure returns (uint256) {
        return uint256(uint160(value));
    }
}
