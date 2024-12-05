// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "../libraries/Message.sol";

/// @dev The settlement mode
/// @custom:field LockMint means the source chain is locked and the destination chain will mint the tokens
/// @custom:field LockUnlock means the source chain is locked and the destination chain will unlock the tokens
enum SettlementMode {
    MintBurn,
    LockMint,
    LockUnlock
}

// Interface for a settlement handler, responsible for processing cross-chain messages
interface ISettlementHandler {
    /// @notice Emitted when a cross-chain vault deposit is initiated
    /// @param txid Unique identifier of the cross-chain transaction
    /// @param toHandler Address of the handler on the destination chain
    /// @param toChain Name of the destination chain
    /// @param asset Address of the asset token in the vault
    /// @param amount Amount of the asset token in the vault
    /// @param vault The vault address
    /// @param to Address to which the vault will be sent in the destination chain
    /// @param shareReceiver Address of the share receiver from the vault in the destination chain
    /// @param settlementMode Settlement mode
    event CrossChainVaultDepositSend(
        uint256 indexed txid,
        string indexed toChain,
        address indexed toHandler,
        address asset,
        uint256 amount,
        address vault,
        address to,
        address shareReceiver,
        SettlementMode settlementMode
    );

    event CrossChainVaultWithdrawSend(
        uint256 txid,
        string indexed toChain,
        address indexed toHandler,
        address toToken,
        uint256 amount,
        address vault,
        address to,
        SettlementMode settlementMode
    );

    // Callback function invoked when a cross-chain message is received
    //
    // @param txid Unique identifier of the cross-chain transaction
    // @param from_chain Origin chain of the message
    // @param from_handler Handler address on the origin chain
    // @param status Status of the cross-chain message (success, failure, etc.)
    // @param sign_type Type of signature used by validators (e.g., multisig, BLS sr25519)
    // @param signatures Validators' signatures for the message
    function receive_cross_chain_callback(
        uint256 txid,
        string memory from_chain,
        uint256 from_handler,
        CrossChainMsgStatus status,
        uint8 sign_type,
        bytes calldata signatures
    ) external returns (bool);

    // Function to receive a cross-chain message and process its payload
    //
    // @param txid Unique identifier of the cross-chain transaction
    // @param from_chain Origin chain of the message
    // @param from_address Sender address on the origin chain
    // @param from_handler Handler address on the origin chain
    // @param payload_type Type of the message payload
    // @param payload The actual message payload
    // @param sign_type Type of signature used by validators (e.g., multisig, BLS sr25519)
    // @param signatures Validators' signatures for the message
    function receive_cross_chain_msg(
        uint256 txid,
        string memory from_chain,
        uint256 from_address,
        uint256 from_handler,
        PayloadType payload_type,
        bytes calldata payload,
        uint8 sign_type,
        bytes calldata signatures
    ) external returns (bool);
}
