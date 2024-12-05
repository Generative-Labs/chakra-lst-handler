// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

// The Payload type defines the type of payload in the Message
enum PayloadType {
    // Raw payload
    Raw
}

// The Message struct defines the message of corss chain
struct Message {
    // The id of the message
    uint256 id;
    // The type of the payload
    PayloadType payload_type;
    // The payload of the message
    bytes payload;
}

// The CrossChainMsgStatus defines the status of cross chain message
enum CrossChainMsgStatus {
    Unknow,
    Pending,
    Success,
    Failed
}
