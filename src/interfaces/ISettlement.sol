// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {PayloadType} from "../libraries/Message.sol";

interface ISettlement {
    function send_cross_chain_msg(
        string memory to_chain,
        address from_address,
        uint256 to_handler,
        PayloadType payload_type,
        bytes calldata payload
    ) external payable;

    function receive_cross_chain_msg(
        uint256 txid,
        string memory from_chain,
        address from_address,
        uint256 from_handler,
        address to_handler,
        PayloadType payload_type,
        bytes calldata payload,
        uint8 sign_type, // validators signature type /  multisig or bls sr25519
        bytes calldata signatures
    ) external;

    /**
     * @dev get txid for handler
     * @param to_chain The destination chain name
     * @param from_address The from address
     * @param to_handler  The destination handler contract
     */
    function get_txid(string memory to_chain, address from_address, uint256 to_handler)
        external
        view
        returns (uint256 txid);
}
