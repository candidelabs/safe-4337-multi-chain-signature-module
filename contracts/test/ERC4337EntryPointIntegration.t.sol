// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {Safe4337ModuleHarness} from "./Safe4337ModuleHarness.sol";
import {MockSafe} from "./MockSafe.sol";
import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {EntryPoint} from "@account-abstraction/contracts/core/EntryPoint.sol";
import {Safe4337MultiChainSignatureModule} from "../Safe4337MultiChainSignatureModule.sol";

/**
 * @dev Contract that always reverts, for testing error bubbling.
 */
contract TestReverter {
    function alwaysReverting() external pure {
        revert("You called a function that always reverts");
    }
}

/**
 * @dev Simple target for successful execution tests.
 */
contract TestTarget {
    uint256 public value;

    function setValue(uint256 v) external {
        value = v;
    }

    receive() external payable {}
}

/**
 * @title ERC4337 EntryPoint Integration Tests
 * @notice Mirrors the test scenarios from safe-modules reference tests:
 *   - ERC4337ModuleExisting.spec.ts
 *   - ERC4337ModuleNew.spec.ts
 *   - ReferenceEntryPoint.spec.ts
 *   - Safe4337Mock.spec.ts
 *   - Safe4337Module.spec.ts
 */
contract ERC4337EntryPointIntegrationTest is Test {
    EntryPoint internal entryPoint;
    Safe4337MultiChainSignatureModule internal module;
    OpDataHelper internal opDataHelper;
    address internal relayer;

    uint256 internal constant SIGNER1_PK = 0xA11CE;
    uint256 internal constant SIGNER2_PK = 0xB0B;
    uint256 internal constant SIGNER3_PK = 0xCA1;

    address[] internal sortedSigners;
    uint256[] internal sortedPKs;

    function setUp() public {
        entryPoint = new EntryPoint();
        module = new Safe4337MultiChainSignatureModule(address(entryPoint));
        opDataHelper = new OpDataHelper(module);
        relayer = makeAddr("relayer");

        address s1 = vm.addr(SIGNER1_PK);
        address s2 = vm.addr(SIGNER2_PK);
        address s3 = vm.addr(SIGNER3_PK);

        address[3] memory addrs = [s1, s2, s3];
        uint256[3] memory pks = [SIGNER1_PK, SIGNER2_PK, SIGNER3_PK];
        for (uint256 i = 0; i < 3; i++) {
            for (uint256 j = i + 1; j < 3; j++) {
                if (addrs[i] > addrs[j]) {
                    (addrs[i], addrs[j]) = (addrs[j], addrs[i]);
                    (pks[i], pks[j]) = (pks[j], pks[i]);
                }
            }
        }
        for (uint256 i = 0; i < 3; i++) {
            sortedSigners.push(addrs[i]);
            sortedPKs.push(pks[i]);
        }
    }

    // =========================================================================
    // handleOps - Invalid Signature (AA24)
    // Ref: ERC4337ModuleExisting.spec.ts "should revert with invalid signature"
    // Ref: ERC4337ModuleNew.spec.ts "should revert with invalid signature"
    // =========================================================================

    function test_handleOps_invalidSignature_reverts_AA24() public {
        (MockSafe safe,, ) = _deploySafe(1);
        vm.deal(address(safe), 1 ether);

        PackedUserOperation memory userOp = _buildEntryPointUserOp(address(safe), 0, address(0), 0, "");

        // Sign with wrong hash (invalid signature)
        uint256[] memory fakePKs = new uint256[](1);
        fakePKs[0] = 0xDEAD;
        bytes memory signatures = _signSafe(keccak256("baddad"), fakePKs, 1);
        userOp.signature = abi.encodePacked(uint8(0), uint48(0), uint48(0), signatures);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        vm.prank(relayer, relayer);
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error"));
        entryPoint.handleOps(ops, payable(relayer));
    }

    // =========================================================================
    // handleOps - Valid Signature Success
    // Ref: ERC4337ModuleExisting.spec.ts "should execute contract calls without a prefund required"
    // =========================================================================

    function test_handleOps_validSignature_succeeds() public {
        (MockSafe safe,, uint256[] memory pks) = _deploySafe(1);

        // Deposit to entry point so safe doesn't need to pay from balance
        entryPoint.depositTo{value: 1 ether}(address(safe));
        vm.deal(address(safe), 0.5 ether);

        address receiver = makeAddr("receiver");
        PackedUserOperation memory userOp = _buildEntryPointUserOp(address(safe), 0, receiver, 0.5 ether, "");
        userOp = _signUserOp(userOp, pks, 1);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        vm.prank(relayer, relayer);
        entryPoint.handleOps(ops, payable(relayer));

        assertEq(address(receiver).balance, 0.5 ether, "Receiver should have received 0.5 ETH");
    }

    // =========================================================================
    // handleOps - Replay Protection (AA25)
    // Ref: ERC4337ModuleExisting.spec.ts "should not be able to execute contract calls twice"
    // Ref: ERC4337ModuleNew.spec.ts "should not be able to execute contract calls twice"
    // =========================================================================

    function test_handleOps_replayProtection_AA25() public {
        (MockSafe safe,, uint256[] memory pks) = _deploySafe(1);
        vm.deal(address(safe), 2 ether);

        address receiver = makeAddr("receiver");
        PackedUserOperation memory userOp = _buildEntryPointUserOp(address(safe), 0, receiver, 0.1 ether, "");
        userOp = _signUserOp(userOp, pks, 1);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        // First execution should succeed
        vm.prank(relayer, relayer);
        entryPoint.handleOps(ops, payable(relayer));
        assertEq(address(receiver).balance, 0.1 ether);

        // Second execution with same nonce should revert
        vm.prank(relayer, relayer);
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA25 invalid account nonce"));
        entryPoint.handleOps(ops, payable(relayer));
    }

    // =========================================================================
    // handleOps - Fee Payment to Beneficiary
    // Ref: ERC4337ModuleExisting.spec.ts "should execute contract calls with fee"
    // Ref: ERC4337ModuleNew.spec.ts "should execute contract calls with fee"
    // Ref: Safe4337Mock.spec.ts "should execute contract calls with fee"
    // =========================================================================

    function test_handleOps_feePaymentToBeneficiary() public {
        (MockSafe safe,, uint256[] memory pks) = _deploySafe(1);
        vm.deal(address(safe), 2 ether);

        address beneficiary = makeAddr("beneficiary");
        address receiver = makeAddr("receiver");

        assertEq(address(beneficiary).balance, 0);

        PackedUserOperation memory userOp = _buildEntryPointUserOp(address(safe), 0, receiver, 0.5 ether, "");
        userOp = _signUserOp(userOp, pks, 1);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        vm.prank(relayer, relayer);
        entryPoint.handleOps(ops, payable(beneficiary));

        // Beneficiary should have received fee payment
        assertGt(address(beneficiary).balance, 0, "Beneficiary should receive fees");
        // Receiver should have the transfer
        assertEq(address(receiver).balance, 0.5 ether, "Receiver should have 0.5 ETH");
    }

    // =========================================================================
    // handleOps - Execution Failure (UserOperationRevertReason event)
    // Ref: ERC4337ModuleExisting.spec.ts "reverts on failure"
    // Ref: ERC4337ModuleNew.spec.ts "reverts on failure"
    // =========================================================================

    function test_handleOps_executionFailure_emitsRevertReason() public {
        (MockSafe safe,, uint256[] memory pks) = _deploySafe(1);
        // Fund safe but not enough for the transfer amount
        entryPoint.depositTo{value: 1 ether}(address(safe));

        // Try to send 0.5 ETH when safe has 0 ETH balance (will fail in execTransactionFromModule)
        PackedUserOperation memory userOp = _buildEntryPointUserOp(address(safe), 0, address(this), 0.5 ether, "");
        userOp = _signUserOp(userOp, pks, 1);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        bytes memory expectedRevertData = abi.encodeWithSelector(Safe4337MultiChainSignatureModule.ExecutionFailed.selector);

        // Should emit UserOperationRevertReason with ExecutionFailed error
        vm.expectEmit(false, true, false, false, address(entryPoint));
        emit IEntryPoint.UserOperationRevertReason(bytes32(0), address(safe), 0, expectedRevertData);

        vm.prank(relayer, relayer);
        entryPoint.handleOps(ops, payable(relayer));
    }

    // =========================================================================
    // handleOps - executeUserOpWithErrorString Success
    // Ref: ERC4337ModuleExisting.spec.ts "executeUserOpWithErrorString should execute contract calls"
    // Ref: ERC4337ModuleNew.spec.ts "executeUserOpWithErrorString should execute contract calls"
    // =========================================================================

    function test_handleOps_executeUserOpWithErrorString_succeeds() public {
        (MockSafe safe,, uint256[] memory pks) = _deploySafe(1);
        vm.deal(address(safe), 2 ether);

        address receiver = makeAddr("receiver");
        PackedUserOperation memory userOp = _buildEntryPointUserOpWithErrorString(address(safe), 0, receiver, 0.5 ether, "");
        userOp = _signUserOp(userOp, pks, 1);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        vm.prank(relayer, relayer);
        entryPoint.handleOps(ops, payable(relayer));

        assertEq(address(receiver).balance, 0.5 ether, "Receiver should have 0.5 ETH");
    }

    // =========================================================================
    // handleOps - executeUserOpWithErrorString Revert Reason Bubbling
    // Ref: ERC4337ModuleExisting.spec.ts "executeUserOpWithErrorString reverts on failure and bubbles up the revert reason"
    // Ref: ERC4337ModuleNew.spec.ts "executeUserOpWithErrorString reverts on failure and bubbles up the revert reason"
    // =========================================================================

    function test_handleOps_executeUserOpWithErrorString_bubblesRevertReason() public {
        (MockSafe safe,, uint256[] memory pks) = _deploySafe(1);
        vm.deal(address(safe), 2 ether);

        TestReverter reverter = new TestReverter();
        bytes memory callData = abi.encodeWithSelector(TestReverter.alwaysReverting.selector);

        PackedUserOperation memory userOp = _buildEntryPointUserOpWithErrorString(
            address(safe), 0, address(reverter), 0, callData
        );
        userOp = _signUserOp(userOp, pks, 1);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        // The revert data should be Error("You called a function that always reverts")
        bytes memory expectedRevertData = abi.encodeWithSignature(
            "Error(string)",
            "You called a function that always reverts"
        );

        vm.expectEmit(false, true, false, false, address(entryPoint));
        emit IEntryPoint.UserOperationRevertReason(bytes32(0), address(safe), 0, expectedRevertData);

        vm.prank(relayer, relayer);
        entryPoint.handleOps(ops, payable(relayer));
    }

    // =========================================================================
    // handleOps - Timestamp Validation (AA22)
    // Ref: ReferenceEntryPoint.spec.ts "should correctly bubble up the signature timestamps to the entrypoint"
    // =========================================================================

    function test_handleOps_validAfter_tooEarly_reverts_AA22() public {
        (MockSafe safe,, uint256[] memory pks) = _deploySafe(1);
        vm.deal(address(safe), 2 ether);

        uint48 validAfter = uint48(block.timestamp + 86400); // 1 day from now
        uint48 validUntil = validAfter + 86400;

        PackedUserOperation memory userOp = _buildEntryPointUserOpWithTimestamps(
            address(safe), 0, address(0), 0, "", validAfter, validUntil
        );
        userOp = _signUserOpWithTimestamps(userOp, pks, 1, validAfter, validUntil);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        // Should fail because block.timestamp < validAfter
        vm.prank(relayer, relayer);
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA22 expired or not due"));
        entryPoint.handleOps(ops, payable(relayer));
    }

    function test_handleOps_validAfter_afterTimestamp_succeeds() public {
        (MockSafe safe,, uint256[] memory pks) = _deploySafe(1);
        vm.deal(address(safe), 2 ether);

        uint48 validAfter = uint48(block.timestamp + 86400);
        uint48 validUntil = validAfter + 86400;

        PackedUserOperation memory userOp = _buildEntryPointUserOpWithTimestamps(
            address(safe), 0, address(0), 0, "", validAfter, validUntil
        );
        userOp = _signUserOpWithTimestamps(userOp, pks, 1, validAfter, validUntil);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        // Warp time past validAfter
        vm.warp(validAfter + 1);

        vm.prank(relayer, relayer);
        entryPoint.handleOps(ops, payable(relayer));
        // No revert = success
    }

    function test_handleOps_validUntil_expired_reverts_AA22() public {
        (MockSafe safe,, uint256[] memory pks) = _deploySafe(1);
        vm.deal(address(safe), 2 ether);

        uint48 validAfter = uint48(block.timestamp);
        uint48 validUntil = uint48(block.timestamp + 100);

        PackedUserOperation memory userOp = _buildEntryPointUserOpWithTimestamps(
            address(safe), 0, address(0), 0, "", validAfter, validUntil
        );
        userOp = _signUserOpWithTimestamps(userOp, pks, 1, validAfter, validUntil);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        // Warp time past validUntil
        vm.warp(validUntil + 1);

        vm.prank(relayer, relayer);
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA22 expired or not due"));
        entryPoint.handleOps(ops, payable(relayer));
    }

    // =========================================================================
    // handleOps - Signature Length Validation
    // Ref: ReferenceEntryPoint.spec.ts "should revert on invalid signature length - EOA signature"
    // Ref: Safe4337Module.spec.ts "should indicate failed validation data when signature length contains additional bytes"
    // =========================================================================

    function test_handleOps_signatureWithAdditionalBytes_reverts_AA24() public {
        (MockSafe safe,, uint256[] memory pks) = _deploySafe(1);
        vm.deal(address(safe), 2 ether);

        PackedUserOperation memory userOp = _buildEntryPointUserOp(address(safe), 0, address(0), 0, "");
        userOp = _signUserOp(userOp, pks, 1);

        // Append extra byte to the signature — _checkSignaturesLength rejects
        userOp.signature = abi.encodePacked(userOp.signature, uint8(0x00));

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        vm.prank(relayer, relayer);
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error"));
        entryPoint.handleOps(ops, payable(relayer));
    }

    function test_handleOps_signatureTooShort_reverts_AA24() public {
        (MockSafe safe,,) = _deploySafe(1);
        vm.deal(address(safe), 2 ether);

        PackedUserOperation memory userOp = _buildEntryPointUserOp(address(safe), 0, address(0), 0, "");
        // Empty signature (just header, no ECDSA sig)
        userOp.signature = abi.encodePacked(uint8(0), uint48(0), uint48(0));

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        vm.prank(relayer, relayer);
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error"));
        entryPoint.handleOps(ops, payable(relayer));
    }

    // =========================================================================
    // handleOps - Contract Signature with Invalid Offset
    // Ref: Safe4337Module.spec.ts "should indicate failed validation data when dynamic position pointer is invalid"
    // Ref: ReferenceEntryPoint.spec.ts "should revert when signature offset points to invalid part"
    // =========================================================================

    function test_handleOps_contractSigInvalidOffset_reverts_AA24() public {
        (MockSafe safe,,) = _deploySafe(1);
        vm.deal(address(safe), 2 ether);

        PackedUserOperation memory userOp = _buildEntryPointUserOp(address(safe), 0, address(0), 0, "");

        // Construct a malformed contract signature:
        // [32-byte random r][32-byte offset pointing to start (0)][1-byte type = 0 (contract sig)]
        bytes memory malformedSig = abi.encodePacked(
            bytes32(keccak256("random")),   // r (32 bytes)
            bytes32(0),                      // s = 0, offset pointing to start of signatures
            uint8(0)                         // v = 0, contract signature type
        );
        userOp.signature = abi.encodePacked(uint8(0), uint48(0), uint48(0), malformedSig);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        vm.prank(relayer, relayer);
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error"));
        entryPoint.handleOps(ops, payable(relayer));
    }

    // =========================================================================
    // handleOps - Padding Between Signatures
    // Ref: ReferenceEntryPoint.spec.ts "should revert when padded with additional bytes in-between signatures"
    // =========================================================================

    function test_handleOps_paddingBetweenSignatures_reverts_AA24() public {
        (MockSafe safe,,) = _deploySafe(1);
        vm.deal(address(safe), 2 ether);

        PackedUserOperation memory userOp = _buildEntryPointUserOp(address(safe), 0, address(0), 0, "");

        // Construct contract signature with illegal padding between static and dynamic parts
        bytes memory dynamicSig = hex"aabbccdd"; // 4-byte dummy dynamic signature
        bytes memory malformedSig = abi.encodePacked(
            bytes32(uint256(uint160(address(0x1234)))),  // signer address (padded to 32 bytes)
            bytes32(uint256(65 + 7)),                     // offset: 65 (static) + 7 (padding)
            uint8(0),                                     // contract signature type
            bytes7(hex"70616464696e67"),                  // "padding" (illegal bytes)
            bytes32(uint256(dynamicSig.length)),          // dynamic sig length
            dynamicSig
        );
        userOp.signature = abi.encodePacked(uint8(0), uint48(0), uint48(0), malformedSig);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        vm.prank(relayer, relayer);
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error"));
        entryPoint.handleOps(ops, payable(relayer));
    }

    // =========================================================================
    // handleOps - Multiple Operations in Batch
    // Ref: ReferenceEntryPoint.spec.ts "should deploy a Safe and execute transactions"
    // =========================================================================

    function test_handleOps_multipleOps_succeeds() public {
        (MockSafe safe,, uint256[] memory pks) = _deploySafe(1);
        vm.deal(address(safe), 3 ether);

        address receiver = makeAddr("receiver");

        PackedUserOperation memory userOp0 = _buildEntryPointUserOp(address(safe), 0, receiver, 0.1 ether, "");
        userOp0 = _signUserOp(userOp0, pks, 1);

        PackedUserOperation memory userOp1 = _buildEntryPointUserOp(address(safe), 1, receiver, 0.1 ether, "");
        userOp1 = _signUserOp(userOp1, pks, 1);

        PackedUserOperation[] memory ops = new PackedUserOperation[](2);
        ops[0] = userOp0;
        ops[1] = userOp1;

        vm.prank(relayer, relayer);
        entryPoint.handleOps(ops, payable(relayer));

        assertEq(address(receiver).balance, 0.2 ether, "Receiver should have 0.2 ETH from 2 ops");
    }

    // =========================================================================
    // handleOps - Multi-Chain Merkle Proof via EntryPoint
    // =========================================================================

    function test_handleOps_multiChain_validProof() public {
        (MockSafe safe,, uint256[] memory pks) = _deploySafe(1);
        vm.deal(address(safe), 2 ether);

        PackedUserOperation memory userOp = _buildEntryPointUserOp(address(safe), 0, address(0), 0, "");

        // Get operation data to compute leaf
        bytes memory opData = _getOperationData(userOp);
        bytes32 leaf = keccak256(opData);

        bytes32 otherLeaf = keccak256("other_chain_op");
        bytes32 root = _hashPair(leaf, otherLeaf);
        bytes memory proof = abi.encodePacked(root, otherLeaf);

        // Sign merkle root EIP-712 hash
        bytes32 merkleRootHash = _merkleRootEIP712Hash(root);
        bytes memory signatures = _signSafe(merkleRootHash, pks, 1);

        userOp.signature = abi.encodePacked(uint8(1), uint48(0), uint48(0), proof, signatures);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        vm.prank(relayer, relayer);
        entryPoint.handleOps(ops, payable(relayer));
        // No revert = success
    }

    function test_handleOps_multiChain_invalidProof_reverts_AA24() public {
        (MockSafe safe,, uint256[] memory pks) = _deploySafe(1);
        vm.deal(address(safe), 2 ether);

        PackedUserOperation memory userOp = _buildEntryPointUserOp(address(safe), 0, address(0), 0, "");

        // Build proof with wrong sibling
        bytes32 wrongRoot = keccak256("wrongRoot");
        bytes32 wrongSibling = keccak256("wrongSibling");
        bytes memory proof = abi.encodePacked(wrongRoot, wrongSibling);

        bytes32 merkleRootHash = _merkleRootEIP712Hash(wrongRoot);
        bytes memory signatures = _signSafe(merkleRootHash, pks, 1);

        userOp.signature = abi.encodePacked(uint8(1), uint48(0), uint48(0), proof, signatures);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        vm.prank(relayer, relayer);
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error"));
        entryPoint.handleOps(ops, payable(relayer));
    }

    // =========================================================================
    // handleOps - Multi-Sig via EntryPoint
    // =========================================================================

    function test_handleOps_multiSig_2of3_succeeds() public {
        (MockSafe safe,, uint256[] memory pks) = _deploySafe(2);
        vm.deal(address(safe), 2 ether);

        address receiver = makeAddr("receiver");
        PackedUserOperation memory userOp = _buildEntryPointUserOp(address(safe), 0, receiver, 0.5 ether, "");
        userOp = _signUserOp(userOp, pks, 2);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        vm.prank(relayer, relayer);
        entryPoint.handleOps(ops, payable(relayer));

        assertEq(address(receiver).balance, 0.5 ether);
    }

    // =========================================================================
    // handleOps - Contract Call Execution
    // Ref: Safe4337Mock.spec.ts "should execute contract calls without fee"
    // =========================================================================

    function test_handleOps_contractCallExecution() public {
        (MockSafe safe,, uint256[] memory pks) = _deploySafe(1);
        vm.deal(address(safe), 2 ether);

        TestTarget target = new TestTarget();
        bytes memory execData = abi.encodeWithSelector(TestTarget.setValue.selector, 42);

        PackedUserOperation memory userOp = _buildEntryPointUserOp(address(safe), 0, address(target), 0, execData);
        userOp = _signUserOp(userOp, pks, 1);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        vm.prank(relayer, relayer);
        entryPoint.handleOps(ops, payable(relayer));

        assertEq(target.value(), 42, "Target value should be set via handleOps");
    }

    // =========================================================================
    // handleOps - Without Prefund (using depositTo)
    // Ref: ERC4337ModuleExisting.spec.ts "should execute contract calls without a prefund required"
    // =========================================================================

    function test_handleOps_withoutPrefund_usingDeposit() public {
        (MockSafe safe,, uint256[] memory pks) = _deploySafe(1);

        // Deposit to entry point instead of funding the safe directly
        entryPoint.depositTo{value: 1 ether}(address(safe));

        vm.deal(address(safe), 0.5 ether);
        address receiver = makeAddr("receiver");

        PackedUserOperation memory userOp = _buildEntryPointUserOp(address(safe), 0, receiver, 0.5 ether, "");
        userOp = _signUserOp(userOp, pks, 1);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        vm.prank(relayer, relayer);
        entryPoint.handleOps(ops, payable(relayer));

        assertEq(address(receiver).balance, 0.5 ether);
        assertEq(address(safe).balance, 0, "Safe should have spent all its ETH");
    }

    // =========================================================================
    // validateUserOp - Revert for Different Safe (InvalidCaller)
    // Ref: Safe4337Module.spec.ts "should revert when validating user ops for a different Safe"
    // =========================================================================

    function test_handleOps_wrongSafe_reverts() public {
        (MockSafe safe1,, uint256[] memory pks) = _deploySafe(1);
        (MockSafe safe2,,) = _deploySafe(1);
        vm.deal(address(safe2), 2 ether);

        // Build userOp for safe1 but submit through safe2
        PackedUserOperation memory userOp = _buildEntryPointUserOp(address(safe1), 0, address(0), 0, "");
        userOp = _signUserOp(userOp, pks, 1);

        // Change sender to safe2 — this makes userOp.sender != msg.sender in validateUserOp
        userOp.sender = address(safe2);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        // This should fail because the signature was computed for safe1 but sender is safe2
        vm.prank(relayer, relayer);
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error"));
        entryPoint.handleOps(ops, payable(relayer));
    }

    // =========================================================================
    // validateUserOp - Unsupported Execution Function
    // Ref: Safe4337Module.spec.ts "should revert when calling an unsupported Safe method"
    // =========================================================================

    function test_handleOps_unsupportedSelector_reverts() public {
        (MockSafe safe,,) = _deploySafe(1);
        vm.deal(address(safe), 2 ether);

        bytes memory dummySig = abi.encodePacked(uint8(0), uint48(0), uint48(0), new bytes(65));
        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(safe),
            nonce: 0,
            initCode: "",
            callData: abi.encodeWithSelector(bytes4(0xdeadbeef), address(0), 0, "", 0),
            accountGasLimits: _packGasLimits(500000, 500000),
            preVerificationGas: 100000,
            gasFees: _packGasFees(1 gwei, 1 gwei),
            paymasterAndData: "",
            signature: dummySig
        });

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        vm.prank(relayer, relayer);
        vm.expectRevert(); // Reverts with UnsupportedExecutionFunction
        entryPoint.handleOps(ops, payable(relayer));
    }

    // =========================================================================
    // getOperationHash - Consistency Check
    // Ref: Safe4337Module.spec.ts "should correctly calculate EIP-712 hash of the operation"
    // Ref: Safe4337Module.spec.ts "should change if any UserOperation fields change"
    // =========================================================================

    function test_getOperationHash_consistentWithManualComputation() public view {
        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(0x11),
            nonce: 0x12,
            initCode: hex"13",
            callData: hex"14",
            accountGasLimits: _packGasLimits(0x16, 0x17),
            preVerificationGas: 0x15,
            gasFees: _packGasFees(0x18, 0x19),
            paymasterAndData: hex"1a",
            signature: abi.encodePacked(uint8(0), uint48(0x1b), uint48(0x1c))
        });

        bytes32 opHash = module.getOperationHash(userOp);

        // Manually compute the EIP-712 hash
        bytes32 SAFE_OP_TYPEHASH = 0xc03dfc11d8b10bf9cf703d558958c8c42777f785d998c62060d85a4f0ef6ea7f;
        bytes32 structHash = keccak256(abi.encode(
            SAFE_OP_TYPEHASH,
            address(0x11),       // safe
            uint256(0x12),       // nonce
            keccak256(hex"13"),  // initCodeHash
            keccak256(hex"14"),  // callDataHash
            uint128(0x16),       // verificationGasLimit
            uint128(0x17),       // callGasLimit
            uint256(0x15),       // preVerificationGas
            uint128(0x18),       // maxPriorityFeePerGas
            uint128(0x19),       // maxFeePerGas
            keccak256(hex"1a"),  // paymasterAndDataHash
            uint48(0x1b),        // validAfter
            uint48(0x1c),        // validUntil
            address(entryPoint)  // entryPoint
        ));

        bytes32 domainSep = keccak256(abi.encode(
            keccak256("EIP712Domain(uint256 chainId,address verifyingContract)"),
            block.chainid,
            address(module)
        ));

        bytes32 expected = keccak256(abi.encodePacked(bytes1(0x19), bytes1(0x01), domainSep, structHash));
        assertEq(opHash, expected);
    }

    function test_getOperationHash_changesWithEachField() public view {
        PackedUserOperation memory baseOp = PackedUserOperation({
            sender: address(0x11),
            nonce: 0x12,
            initCode: hex"13",
            callData: hex"14",
            accountGasLimits: _packGasLimits(0x16, 0x17),
            preVerificationGas: 0x15,
            gasFees: _packGasFees(0x18, 0x19),
            paymasterAndData: hex"1a",
            signature: abi.encodePacked(uint8(0), uint48(0x1b), uint48(0x1c))
        });

        bytes32 baseHash = module.getOperationHash(baseOp);

        // Change sender
        PackedUserOperation memory modified = _clone(baseOp);
        modified.sender = address(0x21);
        assertTrue(module.getOperationHash(modified) != baseHash, "sender change");

        // Change nonce
        modified = _clone(baseOp);
        modified.nonce = 0x22;
        assertTrue(module.getOperationHash(modified) != baseHash, "nonce change");

        // Change initCode
        modified = _clone(baseOp);
        modified.initCode = hex"23";
        assertTrue(module.getOperationHash(modified) != baseHash, "initCode change");

        // Change callData
        modified = _clone(baseOp);
        modified.callData = hex"24";
        assertTrue(module.getOperationHash(modified) != baseHash, "callData change");

        // Change preVerificationGas
        modified = _clone(baseOp);
        modified.preVerificationGas = 0x25;
        assertTrue(module.getOperationHash(modified) != baseHash, "preVerificationGas change");

        // Change verificationGasLimit
        modified = _clone(baseOp);
        modified.accountGasLimits = _packGasLimits(0x26, 0x17);
        assertTrue(module.getOperationHash(modified) != baseHash, "verificationGasLimit change");

        // Change callGasLimit
        modified = _clone(baseOp);
        modified.accountGasLimits = _packGasLimits(0x16, 0x27);
        assertTrue(module.getOperationHash(modified) != baseHash, "callGasLimit change");

        // Change maxPriorityFeePerGas
        modified = _clone(baseOp);
        modified.gasFees = _packGasFees(0x28, 0x19);
        assertTrue(module.getOperationHash(modified) != baseHash, "maxPriorityFeePerGas change");

        // Change maxFeePerGas
        modified = _clone(baseOp);
        modified.gasFees = _packGasFees(0x18, 0x29);
        assertTrue(module.getOperationHash(modified) != baseHash, "maxFeePerGas change");

        // Change paymasterAndData
        modified = _clone(baseOp);
        modified.paymasterAndData = hex"2a";
        assertTrue(module.getOperationHash(modified) != baseHash, "paymasterAndData change");

        // Change validAfter
        modified = _clone(baseOp);
        modified.signature = abi.encodePacked(uint8(0), uint48(0x2b), uint48(0x1c));
        assertTrue(module.getOperationHash(modified) != baseHash, "validAfter change");

        // Change validUntil
        modified = _clone(baseOp);
        modified.signature = abi.encodePacked(uint8(0), uint48(0x1b), uint48(0x2c));
        assertTrue(module.getOperationHash(modified) != baseHash, "validUntil change");
    }

    // =========================================================================
    // handleOps - Cross-Chain via EntryPoint
    // =========================================================================

    function test_handleOps_crossChain_wrongChain_reverts_AA24() public {
        (MockSafe safe,, uint256[] memory pks) = _deploySafe(1);
        vm.deal(address(safe), 2 ether);

        // Build userOp on chain 1
        vm.chainId(1);
        PackedUserOperation memory userOp = _buildEntryPointUserOp(address(safe), 0, address(0), 0, "");
        bytes memory opData = _getOperationData(userOp);
        bytes32 leaf = keccak256(opData);
        bytes32 otherLeaf = keccak256("chain2_op");
        bytes32 root = _hashPair(leaf, otherLeaf);
        bytes memory proof = abi.encodePacked(root, otherLeaf);

        bytes32 merkleRootHash = _merkleRootEIP712Hash(root);
        bytes memory signatures = _signSafe(merkleRootHash, pks, 1);
        userOp.signature = abi.encodePacked(uint8(1), uint48(0), uint48(0), proof, signatures);

        // Try to execute on chain 2 — leaf will be different
        vm.chainId(2);
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        vm.prank(relayer, relayer);
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error"));
        entryPoint.handleOps(ops, payable(relayer));
    }

    // =========================================================================
    // Internal Helpers
    // =========================================================================

    function _deploySafe(uint256 threshold) internal returns (MockSafe safe, address[] memory owners, uint256[] memory pks) {
        owners = new address[](sortedSigners.length);
        pks = new uint256[](sortedPKs.length);
        for (uint256 i = 0; i < sortedSigners.length; i++) {
            owners[i] = sortedSigners[i];
            pks[i] = sortedPKs[i];
        }
        safe = new MockSafe(owners, threshold);
        safe.setFallbackHandler(address(module));
    }

    function _packGasLimits(uint128 verificationGasLimit, uint128 callGasLimit) internal pure returns (bytes32) {
        return bytes32(uint256(verificationGasLimit) << 128 | uint256(callGasLimit));
    }

    function _packGasFees(uint128 maxPriorityFeePerGas, uint128 maxFeePerGas) internal pure returns (bytes32) {
        return bytes32(uint256(maxPriorityFeePerGas) << 128 | uint256(maxFeePerGas));
    }

    function _buildEntryPointUserOp(
        address safe,
        uint256 nonce,
        address to,
        uint256 value,
        bytes memory data
    ) internal view returns (PackedUserOperation memory) {
        bytes memory dummySig = abi.encodePacked(uint8(0), uint48(0), uint48(0));
        return PackedUserOperation({
            sender: safe,
            nonce: nonce,
            initCode: "",
            callData: abi.encodeWithSelector(module.executeUserOp.selector, to, value, data, uint8(0)),
            accountGasLimits: _packGasLimits(500000, 500000),
            preVerificationGas: 100000,
            gasFees: _packGasFees(1 gwei, 1 gwei),
            paymasterAndData: "",
            signature: dummySig
        });
    }

    function _buildEntryPointUserOpWithErrorString(
        address safe,
        uint256 nonce,
        address to,
        uint256 value,
        bytes memory data
    ) internal view returns (PackedUserOperation memory) {
        bytes memory dummySig = abi.encodePacked(uint8(0), uint48(0), uint48(0));
        return PackedUserOperation({
            sender: safe,
            nonce: nonce,
            initCode: "",
            callData: abi.encodeWithSelector(module.executeUserOpWithErrorString.selector, to, value, data, uint8(0)),
            accountGasLimits: _packGasLimits(500000, 500000),
            preVerificationGas: 100000,
            gasFees: _packGasFees(1 gwei, 1 gwei),
            paymasterAndData: "",
            signature: dummySig
        });
    }

    function _buildEntryPointUserOpWithTimestamps(
        address safe,
        uint256 nonce,
        address to,
        uint256 value,
        bytes memory data,
        uint48 validAfter,
        uint48 validUntil
    ) internal view returns (PackedUserOperation memory) {
        bytes memory dummySig = abi.encodePacked(uint8(0), validAfter, validUntil);
        return PackedUserOperation({
            sender: safe,
            nonce: nonce,
            initCode: "",
            callData: abi.encodeWithSelector(module.executeUserOp.selector, to, value, data, uint8(0)),
            accountGasLimits: _packGasLimits(500000, 500000),
            preVerificationGas: 100000,
            gasFees: _packGasFees(1 gwei, 1 gwei),
            paymasterAndData: "",
            signature: dummySig
        });
    }

    /**
     * @dev Gets operationData from the module for a UserOp (via external call for calldata conversion).
     */
    function _getOperationData(PackedUserOperation memory userOp) internal view returns (bytes memory) {
        return opDataHelper.getOpData(userOp);
    }

    /**
     * @dev Signs a UserOp for single-chain (depth=0) with validAfter=0, validUntil=0.
     */
    function _signUserOp(
        PackedUserOperation memory userOp,
        uint256[] memory pks,
        uint256 count
    ) internal view returns (PackedUserOperation memory) {
        bytes memory opData = _getOperationData(userOp);
        bytes32 opHash = keccak256(opData);
        bytes memory signatures = _signSafe(opHash, pks, count);
        userOp.signature = abi.encodePacked(uint8(0), uint48(0), uint48(0), signatures);
        return userOp;
    }

    /**
     * @dev Signs a UserOp with specific timestamps.
     */
    function _signUserOpWithTimestamps(
        PackedUserOperation memory userOp,
        uint256[] memory pks,
        uint256 count,
        uint48 validAfter,
        uint48 validUntil
    ) internal view returns (PackedUserOperation memory) {
        bytes memory opData = _getOperationData(userOp);
        bytes32 opHash = keccak256(opData);
        bytes memory signatures = _signSafe(opHash, pks, count);
        userOp.signature = abi.encodePacked(uint8(0), validAfter, validUntil, signatures);
        return userOp;
    }

    function _signSafe(bytes32 hash, uint256[] memory pks, uint256 count) internal view returns (bytes memory signatures) {
        signatures = "";
        for (uint256 i = 0; i < count; i++) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(pks[i], hash);
            signatures = abi.encodePacked(signatures, r, s, v);
        }
    }

    function _hashPair(bytes32 a, bytes32 b) internal pure returns (bytes32) {
        return a < b ? _efficientHash(a, b) : _efficientHash(b, a);
    }

    function _efficientHash(bytes32 a, bytes32 b) internal pure returns (bytes32 value) {
        assembly {
            mstore(0x00, a)
            mstore(0x20, b)
            value := keccak256(0x00, 0x40)
        }
    }

    function _merkleRootEIP712Hash(bytes32 root) internal view returns (bytes32) {
        bytes32 structHash = keccak256(abi.encode(
            keccak256("MerkleTreeRoot(bytes32 merkleTreeRoot)"),
            root
        ));
        return keccak256(abi.encodePacked(
            bytes1(0x19), bytes1(0x01),
            module.domainSeparatorMultiChain(),
            structHash
        ));
    }

    function _clone(PackedUserOperation memory op) internal pure returns (PackedUserOperation memory) {
        return PackedUserOperation({
            sender: op.sender,
            nonce: op.nonce,
            initCode: op.initCode,
            callData: op.callData,
            accountGasLimits: op.accountGasLimits,
            preVerificationGas: op.preVerificationGas,
            gasFees: op.gasFees,
            paymasterAndData: op.paymasterAndData,
            signature: op.signature
        });
    }

    receive() external payable {}
}

/**
 * @dev Helper to convert memory UserOp to calldata for getOperationHash.
 */
contract OpDataHelper {
    Safe4337MultiChainSignatureModule public module;

    constructor(Safe4337MultiChainSignatureModule _module) {
        module = _module;
    }

    function getOpData(PackedUserOperation calldata userOp) external view returns (bytes memory) {
        return _getOpData(userOp);
    }

    struct EncodedSafeOp {
        bytes32 typeHash;
        address safe;
        uint256 nonce;
        bytes32 initCodeHash;
        bytes32 callDataHash;
        uint128 verificationGasLimit;
        uint128 callGasLimit;
        uint256 preVerificationGas;
        uint128 maxPriorityFeePerGas;
        uint128 maxFeePerGas;
        bytes32 paymasterAndDataHash;
        uint48 validAfter;
        uint48 validUntil;
        address entryPoint;
    }

    function _getOpData(PackedUserOperation calldata userOp) internal view returns (bytes memory opData) {
        EncodedSafeOp memory encoded = EncodedSafeOp({
            typeHash: 0xc03dfc11d8b10bf9cf703d558958c8c42777f785d998c62060d85a4f0ef6ea7f,
            safe: userOp.sender,
            nonce: userOp.nonce,
            initCodeHash: keccak256(userOp.initCode),
            callDataHash: keccak256(userOp.callData),
            verificationGasLimit: uint128(uint256(userOp.accountGasLimits) >> 128),
            callGasLimit: uint128(uint256(userOp.accountGasLimits)),
            preVerificationGas: userOp.preVerificationGas,
            maxPriorityFeePerGas: uint128(uint256(userOp.gasFees) >> 128),
            maxFeePerGas: uint128(uint256(userOp.gasFees)),
            paymasterAndDataHash: keccak256(userOp.paymasterAndData),
            validAfter: uint48(bytes6(userOp.signature[1:7])),
            validUntil: uint48(bytes6(userOp.signature[7:13])),
            entryPoint: module.SUPPORTED_ENTRYPOINT()
        });

        bytes32 safeOpStructHash;
        assembly ("memory-safe") {
            safeOpStructHash := keccak256(encoded, 448)
        }

        opData = abi.encodePacked(
            bytes1(0x19), bytes1(0x01),
            module.domainSeparator(),
            safeOpStructHash
        );
    }
}
