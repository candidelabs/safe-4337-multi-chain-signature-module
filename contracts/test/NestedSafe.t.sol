// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {EntryPoint} from "@account-abstraction/contracts/core/EntryPoint.sol";
import {Safe4337MultiChainSignatureModule} from "../Safe4337MultiChainSignatureModule.sol";
import {ISafe} from "../Safe.sol";

// =========================================================================
// MockSafe with EIP-1271 contract signature support
// =========================================================================

/**
 * @title MockSafeEIP1271
 * @dev Extends the base MockSafe concept to support both ECDSA (v >= 27) and
 *      contract signatures (v = 0) following the Safe signature encoding format.
 *      For contract signatures, the signer must implement EIP-1271 isValidSignature.
 */
contract MockSafeEIP1271 is ISafe {
    uint256 private _threshold;
    address[] private _owners;
    mapping(address => bool) private _isOwner;
    address private _fallbackHandler;

    constructor(address[] memory owners_, uint256 threshold_) {
        require(threshold_ > 0 && threshold_ <= owners_.length, "Invalid threshold");
        _threshold = threshold_;
        _owners = owners_;
        for (uint256 i = 0; i < owners_.length; i++) {
            _isOwner[owners_[i]] = true;
        }
    }

    function setFallbackHandler(address handler) external {
        _fallbackHandler = handler;
    }

    function getThreshold() external view override returns (uint256) {
        return _threshold;
    }

    /**
     * @dev Validates signatures supporting both ECDSA and contract (EIP-1271) signatures.
     *      Safe signature format per signer:
     *        - ECDSA (v >= 27): [r(32) | s(32) | v(1)] = 65 bytes static
     *        - Contract (v = 0): [signer(32) | offset(32) | v=0(1)] = 65 bytes static
     *          + dynamic part at offset: [length(32) | signature(length)]
     */
    function checkSignatures(
        bytes32 dataHash,
        bytes memory data,
        bytes memory signatures
    ) external view override {
        uint256 threshold = _threshold;
        require(signatures.length >= threshold * 65, "Signatures too short");

        address lastOwner = address(0);
        for (uint256 i = 0; i < threshold; i++) {
            (uint8 v, bytes32 r, bytes32 s) = _signatureSplit(signatures, i);

            address currentOwner;
            if (v == 0) {
                // Contract signature (EIP-1271)
                currentOwner = address(uint160(uint256(r)));
                uint256 offset = uint256(s);
                // Read dynamic signature from offset
                bytes memory contractSignature;
                assembly {
                    // Length is at signatures + 0x20 + offset
                    let sigLen := mload(add(add(signatures, 0x20), offset))
                    contractSignature := mload(0x40)
                    mstore(contractSignature, sigLen)
                    // Copy signature data
                    let src := add(add(signatures, 0x40), offset)
                    let dest := add(contractSignature, 0x20)
                    for { let j := 0 } lt(j, sigLen) { j := add(j, 0x20) } {
                        mstore(add(dest, j), mload(add(src, j)))
                    }
                    mstore(0x40, add(dest, sigLen))
                }
                // Call EIP-1271 isValidSignature on the signer contract
                (bool success, bytes memory result) = currentOwner.staticcall(
                    abi.encodeWithSignature("isValidSignature(bytes32,bytes)", dataHash, contractSignature)
                );
                require(success && result.length >= 32, "EIP-1271 call failed");
                bytes4 magicValue;
                assembly {
                    magicValue := mload(add(result, 0x20))
                }
                require(magicValue == bytes4(0x1626ba7e), "EIP-1271 invalid");
            } else if (v == 1) {
                // Approved hash (pre-validated)
                currentOwner = address(uint160(uint256(r)));
            } else {
                // ECDSA signature
                currentOwner = ecrecover(dataHash, v, r, s);
                require(currentOwner != address(0), "Invalid ECDSA signature");
            }

            require(_isOwner[currentOwner], "Not an owner");
            require(currentOwner > lastOwner, "Signatures not sorted");
            lastOwner = currentOwner;
        }
    }

    function execTransactionFromModule(
        address to,
        uint256 value,
        bytes memory data,
        uint8 operation
    ) external override returns (bool success) {
        if (operation == 0) {
            (success,) = to.call{value: value}(data);
        } else {
            (success,) = to.delegatecall(data);
        }
    }

    function execTransactionFromModuleReturnData(
        address to,
        uint256 value,
        bytes memory data,
        uint8 operation
    ) external override returns (bool success, bytes memory returnData) {
        if (operation == 0) {
            (success, returnData) = to.call{value: value}(data);
        } else {
            (success, returnData) = to.delegatecall(data);
        }
    }

    function domainSeparator() external view override returns (bytes32) {
        return keccak256(abi.encode(
            keccak256("EIP712Domain(uint256 chainId,address verifyingContract)"),
            block.chainid,
            address(this)
        ));
    }

    function getModulesPaginated(
        address,
        uint256
    ) external pure override returns (address[] memory array, address next) {
        array = new address[](0);
        next = address(0);
    }

    function enableModule(address) external override {}

    /**
     * @dev EIP-1271: This Safe validates signatures by calling checkSignatures on itself.
     */
    function isValidSignature(bytes32 hash, bytes memory signature) external view returns (bytes4) {
        this.checkSignatures(hash, abi.encodePacked(hash), signature);
        return bytes4(0x1626ba7e);
    }

    fallback() external payable {
        address handler = _fallbackHandler;
        require(handler != address(0), "No fallback handler");
        assembly {
            calldatacopy(0, 0, calldatasize())
            mstore(calldatasize(), shl(96, caller()))
            let result := call(gas(), handler, 0, 0, add(calldatasize(), 20), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    receive() external payable {}

    function _signatureSplit(
        bytes memory signatures,
        uint256 pos
    ) internal pure returns (uint8 v, bytes32 r, bytes32 s) {
        assembly {
            let signaturePos := mul(0x41, pos)
            r := mload(add(signatures, add(signaturePos, 0x20)))
            s := mload(add(signatures, add(signaturePos, 0x40)))
            v := byte(0, mload(add(signatures, add(signaturePos, 0x60))))
        }
    }
}

/**
 * @title Nested Safe Tests
 * @notice Mirrors test scenarios from safe-modules reference tests:
 *   - 4337NestedSafe.spec.ts: Nested Safe ownership with contract signatures
 * @dev Tests hierarchical Safe ownership where a child Safe acts as owner of a parent Safe,
 *      using EIP-1271 contract signatures for validation through the real EntryPoint.
 */
contract NestedSafeTest is Test {
    EntryPoint internal entryPoint;
    Safe4337MultiChainSignatureModule internal module;
    NestedOpDataHelper internal opDataHelper;
    address internal relayer;

    uint256 internal constant ALICE_PK = 0xA11CE;
    uint256 internal constant BOB_PK = 0xB0B;
    uint256 internal constant CHARLIE_PK = 0xCA1;

    function setUp() public {
        entryPoint = new EntryPoint();
        module = new Safe4337MultiChainSignatureModule(address(entryPoint));
        opDataHelper = new NestedOpDataHelper(module);
        relayer = makeAddr("relayer");
    }

    // =========================================================================
    // Nested Safe: Child Safe owns Parent Safe (1-level nesting)
    // Ref: 4337NestedSafe.spec.ts "should execute a nested Safe operation"
    // =========================================================================

    function test_nestedSafe_childOwnsParent_singleLevel() public {
        // Child Safe: owned by Alice (EOA), threshold = 1
        address alice = vm.addr(ALICE_PK);
        address[] memory childOwners = new address[](1);
        childOwners[0] = alice;
        MockSafeEIP1271 childSafe = new MockSafeEIP1271(childOwners, 1);

        // Parent Safe: owned by childSafe, threshold = 1
        address[] memory parentOwners = new address[](1);
        parentOwners[0] = address(childSafe);
        MockSafeEIP1271 parentSafe = new MockSafeEIP1271(parentOwners, 1);
        parentSafe.setFallbackHandler(address(module));
        vm.deal(address(parentSafe), 5 ether);

        address receiver = makeAddr("receiver");

        // Build the user operation for the parent Safe
        PackedUserOperation memory userOp = _buildUserOp(address(parentSafe), 0, receiver, 1 ether, "");

        // Get operation hash that needs to be signed
        bytes memory opData = opDataHelper.getOpData(userOp);
        bytes32 opHash = keccak256(opData);

        // Alice signs the operation hash (as owner of child Safe)
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE_PK, opHash);
        bytes memory aliceSig = abi.encodePacked(r, s, v);

        // Build contract signature for childSafe as owner of parentSafe
        // Static part: [childSafe address (padded to 32) | offset | v=0]
        // Dynamic part: [length | aliceSig]
        bytes memory contractSig = _buildContractSignature(address(childSafe), aliceSig);

        userOp.signature = abi.encodePacked(uint8(0), uint48(0), uint48(0), contractSig);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        vm.prank(relayer, relayer);
        entryPoint.handleOps(ops, payable(relayer));

        assertEq(receiver.balance, 1 ether, "Receiver should have 1 ETH from nested Safe op");
    }

    // =========================================================================
    // Nested Safe: Mixed ownership (EOA + Contract Signer)
    // Ref: 4337NestedSafe.spec.ts "should execute with mixed EOA and contract signers"
    // =========================================================================

    function test_nestedSafe_mixedOwnership_EOAAndContractSigner() public {
        address alice = vm.addr(ALICE_PK);

        MockSafeEIP1271 childSafe;
        MockSafeEIP1271 parentSafe;
        {
            address bob = vm.addr(BOB_PK);
            address[] memory childOwners = new address[](1);
            childOwners[0] = bob;
            childSafe = new MockSafeEIP1271(childOwners, 1);

            // Sort owners
            address addr1 = alice;
            address addr2 = address(childSafe);
            if (addr1 > addr2) (addr1, addr2) = (addr2, addr1);

            address[] memory parentOwners = new address[](2);
            parentOwners[0] = addr1;
            parentOwners[1] = addr2;
            parentSafe = new MockSafeEIP1271(parentOwners, 2);
            parentSafe.setFallbackHandler(address(module));
            vm.deal(address(parentSafe), 5 ether);
        }

        address receiver = makeAddr("receiver");
        PackedUserOperation memory userOp = _buildUserOp(address(parentSafe), 0, receiver, 1 ether, "");

        bytes memory combinedSig;
        {
            bytes32 opHash = keccak256(opDataHelper.getOpData(userOp));
            bytes memory aliceECDSA = _signWithKey(ALICE_PK, opHash);
            bytes memory bobSig = _signWithKey(BOB_PK, opHash);
            combinedSig = _buildMixedSignature(alice, address(childSafe), aliceECDSA, bobSig);
        }

        userOp.signature = abi.encodePacked(uint8(0), uint48(0), uint48(0), combinedSig);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        vm.prank(relayer, relayer);
        entryPoint.handleOps(ops, payable(relayer));

        assertEq(receiver.balance, 1 ether, "Receiver should have 1 ETH");
    }

    // =========================================================================
    // Nested Safe: 2-level nesting (grandchild -> child -> parent)
    // Ref: 4337NestedSafe.spec.ts "should execute with deeply nested Safe"
    // =========================================================================

    function test_nestedSafe_twoLevelNesting() public {
        // Build 3-level Safe hierarchy: grandchild -> child -> parent
        MockSafeEIP1271 grandchildSafe;
        MockSafeEIP1271 childSafe;
        MockSafeEIP1271 parentSafe;
        {
            address alice = vm.addr(ALICE_PK);
            address[] memory gcOwners = new address[](1);
            gcOwners[0] = alice;
            grandchildSafe = new MockSafeEIP1271(gcOwners, 1);

            address[] memory cOwners = new address[](1);
            cOwners[0] = address(grandchildSafe);
            childSafe = new MockSafeEIP1271(cOwners, 1);

            address[] memory pOwners = new address[](1);
            pOwners[0] = address(childSafe);
            parentSafe = new MockSafeEIP1271(pOwners, 1);
            parentSafe.setFallbackHandler(address(module));
            vm.deal(address(parentSafe), 5 ether);
        }

        address receiver = makeAddr("receiver");
        PackedUserOperation memory userOp = _buildUserOp(address(parentSafe), 0, receiver, 1 ether, "");

        bytes memory childContractSig;
        {
            bytes32 opHash = keccak256(opDataHelper.getOpData(userOp));
            bytes memory aliceSig = _signWithKey(ALICE_PK, opHash);

            // Wrap Alice's ECDSA sig in grandchild contract sig, then wrap that in child contract sig
            bytes memory gcContractSig = _buildContractSignature(address(grandchildSafe), aliceSig);
            childContractSig = _buildContractSignature(address(childSafe), gcContractSig);
        }

        userOp.signature = abi.encodePacked(uint8(0), uint48(0), uint48(0), childContractSig);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        vm.prank(relayer, relayer);
        entryPoint.handleOps(ops, payable(relayer));

        assertEq(receiver.balance, 1 ether, "Receiver should have 1 ETH from 2-level nested Safe");
    }

    // =========================================================================
    // Nested Safe: Invalid contract signature
    // =========================================================================

    function test_nestedSafe_invalidContractSignature_reverts() public {
        MockSafeEIP1271 childSafe;
        MockSafeEIP1271 parentSafe;
        {
            address alice = vm.addr(ALICE_PK);
            address[] memory childOwners = new address[](1);
            childOwners[0] = alice;
            childSafe = new MockSafeEIP1271(childOwners, 1);

            address[] memory parentOwners = new address[](1);
            parentOwners[0] = address(childSafe);
            parentSafe = new MockSafeEIP1271(parentOwners, 1);
            parentSafe.setFallbackHandler(address(module));
            vm.deal(address(parentSafe), 5 ether);
        }

        PackedUserOperation memory userOp = _buildUserOp(address(parentSafe), 0, address(0), 0, "");

        {
            bytes32 opHash = keccak256(opDataHelper.getOpData(userOp));
            // Sign with WRONG key (Charlie, not Alice who owns the child Safe)
            bytes memory wrongSig = _signWithKey(CHARLIE_PK, opHash);
            bytes memory contractSig = _buildContractSignature(address(childSafe), wrongSig);
            userOp.signature = abi.encodePacked(uint8(0), uint48(0), uint48(0), contractSig);
        }

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        vm.prank(relayer, relayer);
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error"));
        entryPoint.handleOps(ops, payable(relayer));
    }

    // =========================================================================
    // Nested Safe: Multi-chain with contract signature
    // =========================================================================

    function test_nestedSafe_multiChain_withContractSignature() public {
        address alice = vm.addr(ALICE_PK);

        // Build nested Safe structure
        MockSafeEIP1271 childSafe;
        MockSafeEIP1271 parentSafe;
        {
            address[] memory childOwners = new address[](1);
            childOwners[0] = alice;
            childSafe = new MockSafeEIP1271(childOwners, 1);

            address[] memory parentOwners = new address[](1);
            parentOwners[0] = address(childSafe);
            parentSafe = new MockSafeEIP1271(parentOwners, 1);
            parentSafe.setFallbackHandler(address(module));
            vm.deal(address(parentSafe), 5 ether);
        }

        address receiver = makeAddr("receiver");
        PackedUserOperation memory userOp = _buildUserOp(address(parentSafe), 0, receiver, 1 ether, "");

        // Build merkle proof and sign
        bytes memory proof;
        bytes memory contractSig;
        {
            bytes memory opData = opDataHelper.getOpData(userOp);
            bytes32 leaf = keccak256(opData);
            bytes32 otherLeaf = keccak256("other_chain_op");
            bytes32 root = _hashPair(leaf, otherLeaf);
            proof = abi.encodePacked(root, otherLeaf);

            bytes32 merkleRootHash = _merkleRootEIP712Hash(root);
            bytes memory aliceSig = _signWithKey(ALICE_PK, merkleRootHash);
            contractSig = _buildContractSignature(address(childSafe), aliceSig);
        }

        userOp.signature = abi.encodePacked(uint8(1), uint48(0), uint48(0), proof, contractSig);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        vm.prank(relayer, relayer);
        entryPoint.handleOps(ops, payable(relayer));

        assertEq(receiver.balance, 1 ether);
    }

    // =========================================================================
    // Nested Safe: Threshold 2 with two contract signers
    // =========================================================================

    function test_nestedSafe_twoContractSigners_threshold2() public {
        // Build two child Safes and a parent Safe
        address first;
        address second;
        uint256 firstPK;
        uint256 secondPK;
        MockSafeEIP1271 parentSafe;
        {
            address alice = vm.addr(ALICE_PK);
            address bob = vm.addr(BOB_PK);

            address[] memory childAOwners = new address[](1);
            childAOwners[0] = alice;
            MockSafeEIP1271 childA = new MockSafeEIP1271(childAOwners, 1);

            address[] memory childBOwners = new address[](1);
            childBOwners[0] = bob;
            MockSafeEIP1271 childB = new MockSafeEIP1271(childBOwners, 1);

            first = address(childA);
            second = address(childB);
            firstPK = ALICE_PK;
            secondPK = BOB_PK;
            if (first > second) {
                (first, second) = (second, first);
                (firstPK, secondPK) = (secondPK, firstPK);
            }

            address[] memory parentOwners = new address[](2);
            parentOwners[0] = first;
            parentOwners[1] = second;
            parentSafe = new MockSafeEIP1271(parentOwners, 2);
            parentSafe.setFallbackHandler(address(module));
            vm.deal(address(parentSafe), 5 ether);
        }

        address receiver = makeAddr("receiver");
        PackedUserOperation memory userOp = _buildUserOp(address(parentSafe), 0, receiver, 1 ether, "");

        bytes memory combinedSig;
        {
            bytes32 opHash = keccak256(opDataHelper.getOpData(userOp));
            bytes memory firstSig = _signWithKey(firstPK, opHash);
            bytes memory secondSig = _signWithKey(secondPK, opHash);
            combinedSig = _buildTwoContractSignatures(first, second, firstSig, secondSig);
        }

        userOp.signature = abi.encodePacked(uint8(0), uint48(0), uint48(0), combinedSig);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        vm.prank(relayer, relayer);
        entryPoint.handleOps(ops, payable(relayer));

        assertEq(receiver.balance, 1 ether);
    }

    // =========================================================================
    // Nested Safe: Timestamps with contract signature
    // =========================================================================

    function test_nestedSafe_withTimestamps() public {
        MockSafeEIP1271 childSafe;
        MockSafeEIP1271 parentSafe;
        {
            address alice = vm.addr(ALICE_PK);
            address[] memory childOwners = new address[](1);
            childOwners[0] = alice;
            childSafe = new MockSafeEIP1271(childOwners, 1);

            address[] memory parentOwners = new address[](1);
            parentOwners[0] = address(childSafe);
            parentSafe = new MockSafeEIP1271(parentOwners, 1);
            parentSafe.setFallbackHandler(address(module));
            vm.deal(address(parentSafe), 5 ether);
        }

        uint48 validAfter = uint48(block.timestamp + 100);
        uint48 validUntil = uint48(block.timestamp + 200);
        address receiver = makeAddr("receiver");

        PackedUserOperation memory userOp = _buildUserOpWithTimestamps(
            address(parentSafe), 0, receiver, 1 ether, "", validAfter, validUntil
        );

        {
            bytes32 opHash = keccak256(opDataHelper.getOpData(userOp));
            bytes memory aliceSig = _signWithKey(ALICE_PK, opHash);
            bytes memory contractSig = _buildContractSignature(address(childSafe), aliceSig);
            userOp.signature = abi.encodePacked(uint8(0), validAfter, validUntil, contractSig);
        }

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        // Should fail because block.timestamp < validAfter
        vm.prank(relayer, relayer);
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA22 expired or not due"));
        entryPoint.handleOps(ops, payable(relayer));

        // Warp to valid time
        vm.warp(validAfter + 1);

        vm.prank(relayer, relayer);
        entryPoint.handleOps(ops, payable(relayer));

        assertEq(receiver.balance, 1 ether);
    }

    // =========================================================================
    // Nested Safe: Multiple operations from nested Safe
    // =========================================================================

    function test_nestedSafe_multipleOps() public {
        MockSafeEIP1271 childSafe;
        MockSafeEIP1271 parentSafe;
        {
            address alice = vm.addr(ALICE_PK);
            address[] memory childOwners = new address[](1);
            childOwners[0] = alice;
            childSafe = new MockSafeEIP1271(childOwners, 1);

            address[] memory parentOwners = new address[](1);
            parentOwners[0] = address(childSafe);
            parentSafe = new MockSafeEIP1271(parentOwners, 1);
            parentSafe.setFallbackHandler(address(module));
            vm.deal(address(parentSafe), 5 ether);
        }

        address r1 = makeAddr("receiver1");
        address r2 = makeAddr("receiver2");

        PackedUserOperation[] memory ops = new PackedUserOperation[](2);

        // Op 0
        {
            PackedUserOperation memory userOp0 = _buildUserOp(address(parentSafe), 0, r1, 0.5 ether, "");
            bytes32 opHash0 = keccak256(opDataHelper.getOpData(userOp0));
            bytes memory sig0 = _buildContractSignature(address(childSafe), _signWithKey(ALICE_PK, opHash0));
            userOp0.signature = abi.encodePacked(uint8(0), uint48(0), uint48(0), sig0);
            ops[0] = userOp0;
        }

        // Op 1
        {
            PackedUserOperation memory userOp1 = _buildUserOp(address(parentSafe), 1, r2, 0.5 ether, "");
            bytes32 opHash1 = keccak256(opDataHelper.getOpData(userOp1));
            bytes memory sig1 = _buildContractSignature(address(childSafe), _signWithKey(ALICE_PK, opHash1));
            userOp1.signature = abi.encodePacked(uint8(0), uint48(0), uint48(0), sig1);
            ops[1] = userOp1;
        }

        vm.prank(relayer, relayer);
        entryPoint.handleOps(ops, payable(relayer));

        assertEq(r1.balance, 0.5 ether);
        assertEq(r2.balance, 0.5 ether);
    }

    // =========================================================================
    // Internal Helpers
    // =========================================================================

    /**
     * @dev Builds a Safe contract signature (v=0) for a single contract signer.
     *      Format: [signer address padded to 32 | offset to dynamic part | v=0]
     *              [dynamic signature length (32 bytes) | inner signature bytes]
     */
    function _buildContractSignature(
        address signer,
        bytes memory innerSignature
    ) internal pure returns (bytes memory) {
        // For a single signer, the dynamic part starts right after the static part (65 bytes)
        uint256 dynamicOffset = 65;
        return abi.encodePacked(
            bytes32(uint256(uint160(signer))),   // r = signer address
            bytes32(dynamicOffset),               // s = offset to dynamic data
            uint8(0),                             // v = 0 (contract signature)
            bytes32(uint256(innerSignature.length)), // dynamic: length
            innerSignature                        // dynamic: signature data
        );
    }

    function _packGasLimits(uint128 verificationGasLimit, uint128 callGasLimit) internal pure returns (bytes32) {
        return bytes32(uint256(verificationGasLimit) << 128 | uint256(callGasLimit));
    }

    function _packGasFees(uint128 maxPriorityFeePerGas, uint128 maxFeePerGas) internal pure returns (bytes32) {
        return bytes32(uint256(maxPriorityFeePerGas) << 128 | uint256(maxFeePerGas));
    }

    function _buildUserOp(
        address safe,
        uint256 nonce,
        address to,
        uint256 value,
        bytes memory data
    ) internal view returns (PackedUserOperation memory) {
        return PackedUserOperation({
            sender: safe,
            nonce: nonce,
            initCode: "",
            callData: abi.encodeWithSelector(module.executeUserOp.selector, to, value, data, uint8(0)),
            accountGasLimits: _packGasLimits(1000000, 1000000),
            preVerificationGas: 100000,
            gasFees: _packGasFees(1 gwei, 1 gwei),
            paymasterAndData: "",
            signature: abi.encodePacked(uint8(0), uint48(0), uint48(0))
        });
    }

    function _buildUserOpWithTimestamps(
        address safe,
        uint256 nonce,
        address to,
        uint256 value,
        bytes memory data,
        uint48 validAfter,
        uint48 validUntil
    ) internal view returns (PackedUserOperation memory) {
        return PackedUserOperation({
            sender: safe,
            nonce: nonce,
            initCode: "",
            callData: abi.encodeWithSelector(module.executeUserOp.selector, to, value, data, uint8(0)),
            accountGasLimits: _packGasLimits(1000000, 1000000),
            preVerificationGas: 100000,
            gasFees: _packGasFees(1 gwei, 1 gwei),
            paymasterAndData: "",
            signature: abi.encodePacked(uint8(0), validAfter, validUntil)
        });
    }

    /**
     * @dev Builds a combined signature for an EOA + contract signer (threshold=2, sorted).
     *      The EOA uses ECDSA (v >= 27), the contract signer uses v=0.
     */
    function _buildMixedSignature(
        address eoaAddr,
        address contractAddr,
        bytes memory eoaSig,
        bytes memory innerContractSig
    ) internal pure returns (bytes memory) {
        uint256 dynamicOffset = 2 * 65;
        bytes memory contractStaticPart = abi.encodePacked(
            bytes32(uint256(uint160(contractAddr))),
            bytes32(dynamicOffset),
            uint8(0)
        );
        bytes memory dynamicPart = abi.encodePacked(
            bytes32(uint256(innerContractSig.length)),
            innerContractSig
        );

        if (eoaAddr < contractAddr) {
            return abi.encodePacked(eoaSig, contractStaticPart, dynamicPart);
        } else {
            return abi.encodePacked(contractStaticPart, eoaSig, dynamicPart);
        }
    }

    /**
     * @dev Builds a combined signature for two contract signers (threshold=2).
     *      Both signers use v=0 contract signature format.
     */
    function _buildTwoContractSignatures(
        address signer1,
        address signer2,
        bytes memory innerSig1,
        bytes memory innerSig2
    ) internal pure returns (bytes memory) {
        uint256 dynamicOffset1 = 2 * 65;
        uint256 dynamicOffset2 = dynamicOffset1 + 32 + innerSig1.length;

        return abi.encodePacked(
            bytes32(uint256(uint160(signer1))), bytes32(dynamicOffset1), uint8(0),
            bytes32(uint256(uint160(signer2))), bytes32(dynamicOffset2), uint8(0),
            bytes32(uint256(innerSig1.length)), innerSig1,
            bytes32(uint256(innerSig2.length)), innerSig2
        );
    }

    function _signWithKey(uint256 pk, bytes32 hash) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, hash);
        return abi.encodePacked(r, s, v);
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

    receive() external payable {}
}

/**
 * @dev Helper to convert memory UserOp to calldata.
 */
contract NestedOpDataHelper {
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
