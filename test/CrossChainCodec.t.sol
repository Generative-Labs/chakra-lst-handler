// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

import "../src/crosschain/CrossChainCodec.sol";

contract CrossChainCodecTest is Test {
    CrossChainCodec public codec;
    address public owner = makeAddr("owner");

    function setUp() public {
        codec = new CrossChainCodec();
        codec.initialize(owner);
    }

    function test_initialize() public view {
        assertEq(codec.owner(), owner);
    }

    function test_cross_chain_payload_codec() public view {
        CrossChainPayload memory payload =
            CrossChainPayload({payloadType: CrossChainPayloadType.LockMint, payload: hex"deadbeef"});
        bytes memory encoded = codec.encode_cross_chain_payload(payload);
        CrossChainPayload memory decoded = codec.decode_cross_chain_payload(encoded);

        assertEq(uint8(decoded.payloadType), uint8(CrossChainPayloadType.LockMint));
        assertEq(decoded.payload, hex"deadbeef");
    }

    function test_cross_chain_mint_lock_codec() public {
        uint256 from = uint256(uint160(makeAddr("from")));
        uint256 to = uint256(uint160(makeAddr("to")));
        uint256 to_token = uint256(uint160(makeAddr("to_token")));
        uint256 amount = 1000;
        bytes memory encoded = codec.encode_cross_chain_mint_lock_payload(
            CrossChainMintLockPayload({from: from, to: to, to_token: to_token, amount: amount})
        );
        CrossChainMintLockPayload memory decoded = codec.decode_cross_chain_mint_lock_payload(encoded);

        assertEq(decoded.from, from);
        assertEq(decoded.to, to);
        assertEq(decoded.to_token, to_token);
        assertEq(decoded.amount, amount);
    }

    function test_cross_chain_burn_unlock_codec() public {
        uint256 from_token = uint256(uint160(makeAddr("from_token")));
        uint256 amount = 1000;
        bytes memory encoded = codec.encode_cross_chain_burn_unlock_payload(
            CrossChainBurnUnlockPayload({from_token: from_token, amount: amount})
        );
        CrossChainBurnUnlockPayload memory decoded = codec.decode_cross_chain_burn_unlock_payload(encoded);

        assertEq(decoded.from_token, from_token);
        assertEq(decoded.amount, amount);
    }
}
