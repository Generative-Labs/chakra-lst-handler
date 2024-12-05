// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "../../src/interfaces/ISettlementHandler.sol";

contract MockChakraSettlement {
    mapping(uint256 => CreatedCrossChainTx) public create_cross_txs;
    mapping(uint256 => ReceivedCrossChainTx) public receive_cross_txs;
    mapping(address => uint256) public nonce_manager;
    uint256 public chain_id;
    string public chain_name;

    /**
     * @dev Struct for created cross-chain transactions
     */
    struct CreatedCrossChainTx {
        uint256 txid;
        string from_chain;
        string to_chain;
        address from_address;
        address from_handler;
        uint256 to_handler;
        bytes payload;
        CrossChainMsgStatus status;
    }

    /**
     * @dev Struct for received cross-chain transactions
     */
    struct ReceivedCrossChainTx {
        uint256 txid;
        string from_chain;
        string to_chain;
        uint256 from_address;
        uint256 from_handler;
        address to_handler;
        bytes payload;
        CrossChainMsgStatus status;
    }

    // Events for cross-chain messages
    event CrossChainMsg(
        uint256 indexed txid,
        address indexed from_address,
        string from_chain,
        string to_chain,
        address from_handler,
        uint256 to_handler,
        PayloadType payload_type,
        bytes payload
    );

    // cross chain handle result emit by receive side
    event CrossChainHandleResult(
        uint256 indexed txid,
        CrossChainMsgStatus status,
        string from_chain,
        string to_chain,
        address from_handler,
        uint256 to_handler,
        PayloadType payload_type
    );

    // Cross Chain result emit by sender side
    event CrossChainResult(
        uint256 indexed txid,
        string from_chain,
        string to_chain,
        address from_address,
        address from_handler,
        uint256 to_handler,
        CrossChainMsgStatus status
    );

    constructor(string memory _chain_name, uint256 _chain_id) {
        chain_id = _chain_id;
        chain_name = _chain_name;
    }

    /**
     * @dev Function to send cross-chain message
     * @param to_chain The chain to send the message to
     * @param from_address The address sending the message
     * @param to_handler The handler to handle the message
     * @param payload_type The type of the payload
     * @param payload The payload of the message
     */
    function send_cross_chain_msg(
        string memory to_chain,
        address from_address,
        uint256 to_handler,
        PayloadType payload_type,
        bytes calldata payload
    ) external {
        nonce_manager[from_address] += 1;

        address from_handler = msg.sender;

        uint256 txid = uint256(
            keccak256(
                abi.encodePacked(
                    chain_name, // from chain
                    to_chain,
                    from_address, // msg.sender address
                    from_handler, // settlement handler address
                    to_handler,
                    nonce_manager[from_address]
                )
            )
        );

        create_cross_txs[txid] = CreatedCrossChainTx(
            txid, chain_name, to_chain, from_address, from_handler, to_handler, payload, CrossChainMsgStatus.Pending
        );

        emit CrossChainMsg(txid, from_address, chain_name, to_chain, from_handler, to_handler, payload_type, payload);
    }

    /**
     * @dev get txid for handler
     * @param to_chain The destination chain name
     * @param from_address The from address
     * @param to_handler  The destination handler contract
     */
    function get_txid(string memory to_chain, address from_address, uint256 to_handler)
        external
        view
        returns (uint256 txid)
    {
        txid = uint256(
            keccak256(
                abi.encodePacked(
                    chain_name, // from chain
                    to_chain,
                    from_address, // msg.sender address
                    msg.sender, // settlement handler address
                    to_handler,
                    nonce_manager[from_address]
                )
            )
        );
    }

    /**
     * @dev Function to receive cross-chain message
     * @param txid The transaction id
     * @param from_chain The chain the message is from
     * @param from_address The address the message is from
     * @param from_handler The handler the message is from
     * @param to_handler The handler to handle the message
     * @param payload_type The type of the payload
     * @param payload The payload of the message
     * @param sign_type The type of the signature
     * @param signatures The signatures of the message
     */
    function receive_cross_chain_msg(
        uint256 txid,
        string memory from_chain,
        uint256 from_address,
        uint256 from_handler,
        address to_handler,
        PayloadType payload_type,
        bytes calldata payload,
        uint8 sign_type, // validators signature type /  multisig or bls sr25519
        bytes calldata signatures // signature array
    ) external {
        require(receive_cross_txs[txid].status == CrossChainMsgStatus.Unknow, "Invalid transaction status");

        receive_cross_txs[txid] = ReceivedCrossChainTx(
            txid,
            from_chain,
            chain_name,
            from_address,
            from_handler,
            address(this),
            payload,
            CrossChainMsgStatus.Pending
        );

        bool result = ISettlementHandler(to_handler).receive_cross_chain_msg(
            txid, from_chain, from_address, from_handler, payload_type, payload, sign_type, signatures
        );

        CrossChainMsgStatus status = CrossChainMsgStatus.Failed;
        if (result == true) {
            status = CrossChainMsgStatus.Success;
            receive_cross_txs[txid].status = CrossChainMsgStatus.Success;
        } else {
            receive_cross_txs[txid].status = CrossChainMsgStatus.Failed;
        }

        emit CrossChainHandleResult(
            txid, status, chain_name, from_chain, address(to_handler), from_handler, payload_type
        );
    }

    /**
     * @dev Function to receive cross-chain callback
     * @param txid The transaction id
     * @param from_chain The chain the callback is from
     * @param from_handler The handler the callback is from
     * @param to_handler The handler to handle the callback
     * @param status The status of the callback
     * @param sign_type The type of the signature
     * @param signatures The signatures of the callback
     */
    function receive_cross_chain_callback(
        uint256 txid,
        string memory from_chain,
        uint256 from_handler,
        address to_handler,
        CrossChainMsgStatus status,
        uint8 sign_type,
        bytes calldata signatures
    ) external {
        processCrossChainCallback(txid, from_chain, from_handler, to_handler, status, sign_type, signatures);
        emitCrossChainResult(txid);
    }

    function processCrossChainCallback(
        uint256 txid,
        string memory from_chain,
        uint256 from_handler,
        address to_handler,
        CrossChainMsgStatus status,
        uint8 sign_type,
        bytes calldata signatures
    ) internal {
        require(create_cross_txs[txid].status == CrossChainMsgStatus.Pending, "Invalid transaction status");

        if (
            ISettlementHandler(to_handler).receive_cross_chain_callback(
                txid, from_chain, from_handler, status, sign_type, signatures
            )
        ) {
            create_cross_txs[txid].status = status;
        } else {
            create_cross_txs[txid].status = CrossChainMsgStatus.Failed;
        }
    }

    function emitCrossChainResult(uint256 txid) internal {
        emit CrossChainResult(
            txid,
            create_cross_txs[txid].from_chain,
            create_cross_txs[txid].to_chain,
            create_cross_txs[txid].from_address,
            create_cross_txs[txid].from_handler,
            create_cross_txs[txid].to_handler,
            create_cross_txs[txid].status
        );
    }
}
