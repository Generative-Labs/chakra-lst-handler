// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import "../interfaces/ISettlement.sol";
import "../libraries/Message.sol";
import "../libraries/MessageV1Codec.sol";
import "../interfaces/ICrossChainCodec.sol";
import "../interfaces/IERC20Mint.sol";
import "../interfaces/IERC20Burn.sol";
import "../interfaces/ISettlementSignatureVerifier.sol";

contract LSTHandler is OwnableUpgradeable, UUPSUpgradeable, AccessControlUpgradeable {
    enum CrossChainTxStatus {
        Unknow,
        Pending,
        Minted,
        Settled,
        Failed
    }

    /// @notice Handler added event
    /// @param chain The chain name
    /// @param handler The handler address
    event HandlerAdded(string indexed chain, address indexed handler);

    /// @notice Handler removed event
    /// @param chain The chain name
    /// @param handler The handler address
    event HandlerRemoved(string indexed chain, address indexed handler);

    event CrossChainMintSended(
        uint256 indexed txid,
        address indexed from,
        uint256 indexed to,
        string from_chain,
        string to_chain,
        address from_token,
        uint256 to_token,
        uint256 amount
    );

    struct CrossChainMintTransaction {
        address sender;
        address to;
        address to_token;
        address to_handler;
        uint256 amount;
    }

    struct CrossChainWithdrawTransaction {
        address sender;
        uint256 amount;
    }

    address public token;
    address public strategy;
    ISettlement public settlement;
    ICrossChainCodec public codec;
    ISettlementSignatureVerifier public signature_verifier;
    uint256 public cross_chain_msg_id_counter;
    mapping(string => mapping(uint256 => bool)) public handle_whitelist;
    mapping(uint256 => CrossChainMintTransaction) public mint_transactions;
    mapping(uint256 => CrossChainWithdrawTransaction) public withdraw_transactions;
    uint64 public cross_chain_msg_id;
    /**
     * @dev The chain name
     */
    string public chain;

    event SentCrossSettlementMsg(
        uint256 txid, string from_chain, string to_chain, address from_handler, address to_handler, bytes payload
    );

    /// @notice Only chakra settlement
    modifier onlySettlement() {
        require(msg.sender == address(settlement), "LSTHandler/not-chakra-settlement");
        _;
    }

    /// @notice Only valid handler
    /// @param _chain The chain name
    /// @param _handler The handler address
    modifier onlyValidHandler(string memory _chain, uint256 _handler) {
        require(handle_whitelist[_chain][_handler], "LSTHandler/not-valid-handler");
        _;
    }

    /// @notice Only strategy
    modifier onlyStrategy() {
        require(msg.sender == strategy, "LSTHandler/not-strategy");
        _;
    }

    /// @notice Initialize the handler
    /// @param _owner The owner address
    /// @param _chain The chain name
    /// @param _strategy The strategy address
    /// @param _token The token address
    /// @param _codec The codec address
    /// @param _settlement The settlement address
    /// @param _signature_verifier The signature verifier address (optional, if you want signature verification)
    function initialize(
        address _owner,
        string memory _chain,
        address _strategy,
        address _token,
        address _codec,
        address _settlement,
        address _signature_verifier
    ) public initializer {
        require(_owner != address(0), "LSTHandler/invalid-owner");
        require(_strategy != address(0), "LSTHandler/invalid-strategy");
        require(_token != address(0), "LSTHandler/invalid-token");
        require(_codec != address(0), "LSTHandler/invalid-codec");
        require(_settlement != address(0), "LSTHandler/invalid-settlement");
        require(_signature_verifier != address(0), "LSTHandler/invalid-signature-verifier");

        __Ownable_init(_owner);
        __UUPSUpgradeable_init();

        settlement = ISettlement(_settlement);
        signature_verifier = ISettlementSignatureVerifier(_signature_verifier);
        codec = ICrossChainCodec(_codec);
        token = _token;
        strategy = _strategy;
        chain = _chain;
        cross_chain_msg_id_counter = 0;
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}

    /// @notice Add a handler
    /// @param _chain The chain name
    /// @param _handler The handler address
    function add_handler(string memory _chain, uint256 _handler) external onlyOwner {
        handle_whitelist[_chain][_handler] = true;
        emit HandlerAdded(_chain, address(uint160(_handler)));
    }

    /// @notice Check if a handler is valid
    /// @param _chain The chain name
    /// @param _handler The handler address
    function is_valid_handler(string memory _chain, uint256 _handler) external view returns (bool) {
        return handle_whitelist[_chain][_handler];
    }

    /// @notice Remove a handler
    /// @param _chain The chain name
    /// @param _handler The handler address
    function remove_handler(string memory _chain, uint256 _handler) external onlyOwner {
        handle_whitelist[_chain][_handler] = false;
        emit HandlerRemoved(_chain, address(uint160(_handler)));
    }

    /// @notice Cross chain mint
    /// @param to_chain The destination chain name
    /// @param to_handler The destination handler address
    /// @param to_token The destination token address
    /// @param to The destination address
    /// @param amount The amount of the mint
    function cross_chain_mint(string memory to_chain, uint256 to_handler, uint256 to_token, uint256 to, uint256 amount)
        external
        onlyStrategy
    {
        require(amount > 0, "LSTHandler/invalid-mint-amount");
        require(to != 0, "LSTHandler/invalid-to-address");
        require(to_handler != 0, "LSTHandler/invalid-to-handler-address");
        require(to_token != 0, "LSTHandler/invalid-to-token-address");

        // 1. Lock token from sender
        require(IERC20(token).balanceOf(msg.sender) >= amount, "LSTHandler/insufficient-balance");
        IERC20(token).transferFrom(msg.sender, address(this), amount);

        // 2. Encode the cross chain msg
        {
            cross_chain_msg_id += 1;

            CrossChainPayload memory cross_chain_payload = CrossChainPayload({
                payloadType: CrossChainPayloadType.LockMint,
                payload: codec.encode_cross_chain_mint_lock_payload(
                    CrossChainMintLockPayload({
                        from: uint256(uint160(msg.sender)),
                        to: to,
                        to_token: to_token,
                        amount: amount
                    })
                )
            });

            Message memory cross_chain_msg =
                Message(cross_chain_msg_id, PayloadType.Raw, codec.encode_cross_chain_payload(cross_chain_payload));
            bytes memory cross_chain_msg_bytes = MessageV1Codec.encode(cross_chain_msg);
            settlement.send_cross_chain_msg(to_chain, msg.sender, to_handler, PayloadType.Raw, cross_chain_msg_bytes);
        }

        uint256 txid = settlement.get_txid(to_chain, msg.sender, to_handler);

        mint_transactions[txid] = CrossChainMintTransaction({
            sender: msg.sender,
            to: address(uint160(to)),
            to_token: address(uint160(to_token)),
            to_handler: address(uint160(to_handler)),
            amount: amount
        });

        emit CrossChainMintSended(txid, msg.sender, to, chain, to_chain, address(uint160(token)), to_token, amount);
    }

    /// @notice Cross chain withdraw
    /// @param to_chain The destination chain name
    /// @param to_handler The destination handler address
    /// @param to_token The destination token address
    /// @param amount The amount of the withdraw
    function cross_chain_withdraw(string memory to_chain, uint256 to_handler, uint256 to_token, uint256 amount)
        external
    {
        require(amount > 0, "LSTHandler/invalid-withdraw-amount");
        require(to_handler != 0, "LSTHandler/invalid-to-handler-address");
        require(to_token != 0, "LSTHandler/invalid-to-token-address");
        // 1. Check user balance
        require(IERC20(token).balanceOf(msg.sender) >= amount, "LSTHandler/insufficient-balance");

        // 2. Burn the token from receiver
        IERC20(token).transferFrom(msg.sender, address(this), amount);
        IERC20Burn(token).burn(amount);

        // 3. Send the cross chain msg
        {
            cross_chain_msg_id += 1;

            CrossChainPayload memory cross_chain_payload = CrossChainPayload({
                payloadType: CrossChainPayloadType.BurnUnlock,
                payload: codec.encode_cross_chain_burn_unlock_payload(
                    CrossChainBurnUnlockPayload({from_token: to_token, amount: amount})
                )
            });

            Message memory cross_chain_msg =
                Message(cross_chain_msg_id, PayloadType.Raw, codec.encode_cross_chain_payload(cross_chain_payload));

            bytes memory cross_chain_msg_bytes = MessageV1Codec.encode(cross_chain_msg);
            settlement.send_cross_chain_msg(to_chain, msg.sender, to_handler, PayloadType.Raw, cross_chain_msg_bytes);
        }

        uint256 txid = settlement.get_txid(to_chain, msg.sender, to_handler);

        withdraw_transactions[txid] = CrossChainWithdrawTransaction({sender: msg.sender, amount: amount});
    }

    /// @notice Receive the cross chain msg
    /// @param txid The transaction id
    /// @param from_chain The source chain name
    /// @param from_address The source address
    /// @param from_handler The source handler address
    /// @param payload_type The payload type
    /// @param payload The payload
    /// @param sign_type The signature type
    /// @param signatures The signatures
    function receive_cross_chain_msg(
        uint256 txid,
        string memory from_chain,
        uint256 from_address,
        uint256 from_handler,
        PayloadType payload_type,
        bytes calldata payload,
        uint8 sign_type,
        bytes calldata signatures
    ) external onlySettlement onlyValidHandler(from_chain, from_handler) returns (bool) {
        // Optional: verify the signature
        {
            bytes32 message_hash = keccak256(
                abi.encodePacked(txid, from_chain, from_address, from_handler, address(this), keccak256(payload))
            );

            require(signature_verifier.verify(message_hash, signatures, sign_type), "LSTHandler/invalid-signature");
        }

        require(txid != 0, "LSTHandler/invalid-txid");
        require(payload_type == PayloadType.Raw, "LSTHandler/invalid-payload-type");

        CrossChainPayload memory cross_chain_payload = codec.decode_cross_chain_payload(MessageV1Codec.payload(payload));
        if (cross_chain_payload.payloadType == CrossChainPayloadType.LockMint) {
            _handler_cross_chain_mint(codec.decode_cross_chain_mint_lock_payload(cross_chain_payload.payload));
        } else if (cross_chain_payload.payloadType == CrossChainPayloadType.BurnUnlock) {
            _handler_cross_chain_unlock(codec.decode_cross_chain_burn_unlock_payload(cross_chain_payload.payload));
        } else {
            // reason: LSTHandler/invalid-payload-type
            return false;
        }

        return true;
    }

    function _handler_cross_chain_mint(CrossChainMintLockPayload memory mint_payload) internal {
        address to = address(uint160(mint_payload.to));
        address to_token = address(uint160(mint_payload.to_token));
        require(to_token == token, "LSTHandler/invalid-to-token");
        require(to != address(0), "LSTHandler/invalid-to-address");
        require(mint_payload.amount > 0, "LSTHandler/invalid-amount");

        // Mint the token to the receiver
        IERC20Mint(token).mint_to(to, mint_payload.amount);
    }

    function _handler_cross_chain_unlock(CrossChainBurnUnlockPayload memory payload) internal {
        address from_token = address(uint160(payload.from_token));
        require(payload.amount > 0, "LSTHandler/invalid-unlock-amount");
        require(from_token == token, "LSTHandler/invalid-to-token");

        // Unlock the token to the sender
        require(IERC20(token).balanceOf(address(this)) >= payload.amount, "LSTHandler/insufficient-balance");
        IERC20(token).transfer(strategy, payload.amount);
    }
}
