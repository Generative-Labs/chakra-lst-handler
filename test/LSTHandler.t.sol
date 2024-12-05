// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

import "../src/crosschain/LSTHandler.sol";
import "../src/crosschain/CrossChainCodec.sol";

import "./mock/MockERC20.sol";
import "./mock/MockChakraSettlement.sol";
import "./mock/MockSettlementSignatureVerifier.sol";
import "forge-std/console.sol";

contract LSTHandlerTest is Test {
    CrossChainCodec public codec;
    address public owner = makeAddr("owner");
    address public strategy = makeAddr("strategy");
    address public validator1;
    uint256 public validator1Pk;
    address public validator2;
    uint256 public validator2Pk;
    address public validator3;
    uint256 public validator3Pk;

    // == Source Chain ==
    uint256 public source_chain_id = 1;
    string public source_chain = "Ethereum";
    MockERC20 public source_token;
    MockChakraSettlement public source_settlement;
    CrossChainCodec public source_codec;
    LSTHandler public source_handler;
    MockSettlementSignatureVerifier public source_signature_verifier;

    // == Destination Chain ==
    uint256 public destination_chain_id = 2;
    string public destination_chain = "B2";
    MockERC20 public destination_token;
    MockChakraSettlement public destination_settlement;
    CrossChainCodec public destination_codec;
    LSTHandler public destination_handler;
    MockSettlementSignatureVerifier public destination_signature_verifier;

    struct CrossChainMsgLog {
        uint256 txid;
        address from_address;
        string from_chain;
        string to_chain;
        address from_handler;
        uint256 to_handler;
        uint8 payload_type;
        bytes payload;
    }

    function setUp() public {
        // make validators
        (validator1, validator1Pk) = makeAddrAndKey("validator1");
        (validator2, validator2Pk) = makeAddrAndKey("validator2");
        (validator3, validator3Pk) = makeAddrAndKey("validator3");
        uint256 required_validators = 2;

        // init source chain
        source_settlement = new MockChakraSettlement(source_chain, source_chain_id);
        source_token = new MockERC20("Source Token", "SRC");
        source_codec = new CrossChainCodec();
        source_codec.initialize(owner);
        source_handler = new LSTHandler();
        source_signature_verifier = new MockSettlementSignatureVerifier();
        source_signature_verifier.initialize(owner, required_validators);
        source_handler.initialize(
            owner,
            source_chain,
            strategy,
            address(source_token),
            address(source_codec),
            address(source_settlement),
            address(source_signature_verifier)
        );

        // init destination chain
        destination_settlement = new MockChakraSettlement(destination_chain, destination_chain_id);
        destination_token = new MockERC20("Destination Token", "DST");
        destination_codec = new CrossChainCodec();
        destination_codec.initialize(owner);
        destination_handler = new LSTHandler();
        destination_signature_verifier = new MockSettlementSignatureVerifier();
        destination_signature_verifier.initialize(owner, required_validators);
        destination_handler.initialize(
            owner,
            destination_chain,
            strategy,
            address(destination_token),
            address(destination_codec),
            address(destination_settlement),
            address(destination_signature_verifier)
        );

        vm.startPrank(owner);
        source_handler.add_handler(destination_chain, uint256(uint160(address(destination_handler))));
        destination_handler.add_handler(source_chain, uint256(uint160(address(source_handler))));
        source_signature_verifier.add_manager(owner);
        source_signature_verifier.add_validator(validator1);
        source_signature_verifier.add_validator(validator2);
        source_signature_verifier.add_validator(validator3);
        destination_signature_verifier.add_manager(owner);
        destination_signature_verifier.add_validator(validator1);
        destination_signature_verifier.add_validator(validator2);
        destination_signature_verifier.add_validator(validator3);
        vm.stopPrank();
    }

    function _getCrossChainMsgLogRoutine(Vm.Log[] memory entries) internal pure returns (CrossChainMsgLog memory log) {
        bytes32 expectedLog = keccak256("CrossChainMsg(uint256,address,string,string,address,uint256,uint8,bytes)");
        for (uint256 i = 0; i < entries.length; i++) {
            if (entries[i].topics[0] == expectedLog) {
                log.txid = uint256(entries[i].topics[1]);
                log.from_address = address(uint160(uint256(entries[i].topics[2])));
                (log.from_chain, log.to_chain, log.from_handler, log.to_handler, log.payload_type, log.payload) =
                    abi.decode(entries[i].data, (string, string, address, uint256, uint8, bytes));
                return log;
            }
        }
        return log;
    }

    function _getSignatures(CrossChainMsgLog memory log) internal view returns (bytes memory) {
        bytes32 message_hash = keccak256(
            abi.encodePacked(
                log.txid,
                log.from_chain,
                uint256(uint160(log.from_address)),
                uint256(uint160(log.from_handler)),
                address(uint160(log.to_handler)),
                keccak256(log.payload)
            )
        );
        console.logBytes32(message_hash);

        bytes memory signatures;
        {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(validator1Pk, message_hash);
            signatures = abi.encodePacked(r, s, v);
            (v, r, s) = vm.sign(validator2Pk, message_hash);
            signatures = bytes.concat(signatures, abi.encodePacked(r, s, v));
            (v, r, s) = vm.sign(validator3Pk, message_hash);
            signatures = bytes.concat(signatures, abi.encodePacked(r, s, v));
        }
        return signatures;
    }

    function test_cross_chain_mint() public {
        uint256 amount = 1000 * 10 ** 18;
        address receiver = makeAddr("receiver");
        {
            source_token.mint_to(strategy, amount);
            vm.startPrank(strategy);
            source_token.approve(address(source_handler), amount);
            vm.stopPrank();
        }

        // cross chain mint
        vm.recordLogs();

        {
            vm.startPrank(strategy);
            source_handler.cross_chain_mint(
                destination_chain,
                uint256(uint160(address(destination_handler))),
                uint256(uint160(address(destination_token))),
                uint256(uint160(receiver)),
                amount
            );
            vm.stopPrank();
        }
        CrossChainMsgLog memory log = _getCrossChainMsgLogRoutine(vm.getRecordedLogs());

        {
            uint8 sign_type = 0;
            bytes memory signatures = _getSignatures(log);
            destination_settlement.receive_cross_chain_msg(
                log.txid,
                log.from_chain,
                uint256(uint160(log.from_address)),
                uint256(uint160(log.from_handler)),
                address(uint160(log.to_handler)),
                PayloadType(log.payload_type),
                log.payload,
                sign_type,
                signatures
            );
        }
        assertEq(source_token.balanceOf(strategy), 0);
        assertEq(destination_token.balanceOf(receiver), amount);
    }

    function test_cross_chain_burn() public {
        uint256 amount = 1000 * 10 ** 18;
        address receiver = makeAddr("receiver");
        {
            source_token.mint_to(strategy, amount);
            vm.startPrank(strategy);
            source_token.approve(address(source_handler), amount);
            vm.stopPrank();
        }

        // 1. cross chain mint
        vm.recordLogs();
        {
            vm.startPrank(strategy);
            source_handler.cross_chain_mint(
                destination_chain,
                uint256(uint160(address(destination_handler))),
                uint256(uint160(address(destination_token))),
                uint256(uint160(receiver)),
                amount
            );
            vm.stopPrank();
        }
        CrossChainMsgLog memory log = _getCrossChainMsgLogRoutine(vm.getRecordedLogs());
        {
            uint8 sign_type = 0;
            bytes memory signatures = _getSignatures(log);
            destination_settlement.receive_cross_chain_msg(
                log.txid,
                log.from_chain,
                uint256(uint160(log.from_address)),
                uint256(uint160(log.from_handler)),
                address(uint160(log.to_handler)),
                PayloadType(log.payload_type),
                log.payload,
                sign_type,
                signatures
            );
        }

        // 2. cross chain withdraw
        vm.recordLogs();
        {
            vm.startPrank(receiver);
            destination_token.approve(address(destination_handler), amount);
            destination_handler.cross_chain_withdraw(
                source_chain, uint256(uint160(address(source_handler))), uint256(uint160(address(source_token))), amount
            );
            vm.stopPrank();
        }
        CrossChainMsgLog memory withdraw_log = _getCrossChainMsgLogRoutine(vm.getRecordedLogs());
        {
            uint8 sign_type = 0;
            bytes memory signatures = _getSignatures(withdraw_log);
            source_settlement.receive_cross_chain_msg(
                withdraw_log.txid,
                withdraw_log.from_chain,
                uint256(uint160(withdraw_log.from_address)),
                uint256(uint160(withdraw_log.from_handler)),
                address(uint160(withdraw_log.to_handler)),
                PayloadType(withdraw_log.payload_type),
                withdraw_log.payload,
                sign_type,
                signatures
            );
        }
        assertEq(destination_token.balanceOf(receiver), 0);
        assertEq(source_token.balanceOf(strategy), amount);
    }
}
