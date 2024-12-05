// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

import "../interfaces/ICrossChainCodec.sol";

contract CrossChainCodec is ICrossChainCodec, OwnableUpgradeable, UUPSUpgradeable {
    function initialize(address owner) public initializer {
        __Ownable_init(owner);
        __UUPSUpgradeable_init();
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}

    /// @inheritdoc ICrossChainCodec
    function encode_cross_chain_payload(CrossChainPayload memory payload) external pure returns (bytes memory) {
        return abi.encode(payload);
    }

    /// @inheritdoc ICrossChainCodec
    function encode_cross_chain_mint_lock_payload(CrossChainMintLockPayload memory payload)
        external
        pure
        returns (bytes memory)
    {
        return abi.encode(payload);
    }

    /// @inheritdoc ICrossChainCodec
    function encode_cross_chain_burn_unlock_payload(CrossChainBurnUnlockPayload memory payload)
        external
        pure
        returns (bytes memory)
    {
        return abi.encode(payload);
    }

    /// @inheritdoc ICrossChainCodec
    function decode_cross_chain_payload(bytes memory data) external pure returns (CrossChainPayload memory) {
        return abi.decode(data, (CrossChainPayload));
    }

    /// @inheritdoc ICrossChainCodec
    function decode_cross_chain_mint_lock_payload(bytes memory data)
        external
        pure
        returns (CrossChainMintLockPayload memory)
    {
        return abi.decode(data, (CrossChainMintLockPayload));
    }

    /// @inheritdoc ICrossChainCodec
    function decode_cross_chain_burn_unlock_payload(bytes memory data)
        external
        pure
        returns (CrossChainBurnUnlockPayload memory)
    {
        return abi.decode(data, (CrossChainBurnUnlockPayload));
    }
}
