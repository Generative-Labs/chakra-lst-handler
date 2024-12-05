// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {SettlementMode} from "../interfaces/ISettlementHandler.sol";

/// @notice The type of cross chain strategy payload
enum CrossChainPayloadType {
    /// @notice Caller invokes on the source chain, then locks on the source chain, and mints on the target chain
    LockMint,
    /// @notice Caller invokes on the target chain, then burns on the target chain, and unlocks on the source chain
    BurnUnlock
}

/// @notice The cross chain payload
struct CrossChainPayload {
    CrossChainPayloadType payloadType;
    bytes payload;
}

/// @notice The cross chain mint payload
struct CrossChainMintLockPayload {
    uint256 from;
    uint256 to;
    uint256 to_token;
    uint256 amount;
}

/// @notice The cross chain burn payload
struct CrossChainBurnUnlockPayload {
    uint256 from_token;
    uint256 amount;
}

interface ICrossChainCodec {
    /// @notice Encode a cross chain payload into a bytes array
    /// @param payload The cross chain payload to encode
    /// @return The encoded bytes array
    function encode_cross_chain_payload(CrossChainPayload memory payload) external pure returns (bytes memory);

    /// @notice Decode a cross chain strategy payload from a bytes array
    /// @param data The bytes array to decode
    /// @return The decoded cross chain payload
    function decode_cross_chain_payload(bytes memory data) external pure returns (CrossChainPayload memory);

    /// @notice Encode a cross chain mint payload into a bytes array
    /// @param payload The cross chain mint payload to encode
    /// @return The encoded bytes array
    function encode_cross_chain_mint_lock_payload(CrossChainMintLockPayload memory payload)
        external
        pure
        returns (bytes memory);

    /// @notice Decode a cross chain mint payload from a bytes array
    /// @param data The bytes array to decode
    /// @return The decoded cross chain mint payload
    function decode_cross_chain_mint_lock_payload(bytes memory data)
        external
        pure
        returns (CrossChainMintLockPayload memory);

    /// @notice Encode a cross chain burn payload into a bytes array
    /// @param payload The cross chain burn payload to encode
    /// @return The encoded bytes array
    function encode_cross_chain_burn_unlock_payload(CrossChainBurnUnlockPayload memory payload)
        external
        pure
        returns (bytes memory);

    /// @notice Decode a cross chain burn payload from a bytes array
    /// @param data The bytes array to decode
    /// @return The decoded cross chain burn payload
    function decode_cross_chain_burn_unlock_payload(bytes memory data)
        external
        pure
        returns (CrossChainBurnUnlockPayload memory);
}
