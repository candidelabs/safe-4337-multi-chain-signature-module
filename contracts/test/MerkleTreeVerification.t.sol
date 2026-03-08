// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {Safe4337ModuleHarness} from "./Safe4337ModuleHarness.sol";
import {MockSafe} from "./MockSafe.sol";
import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {Safe4337MultiChainSignatureModule} from "../Safe4337MultiChainSignatureModule.sol";

/**
 * @title Wrapper that converts memory UserOps to calldata by calling the harness externally.
 * @dev Since Solidity doesn't allow memory-to-calldata conversion within the same contract,
 *      we use this intermediary to forward calls.
 */
contract HarnessProxy {
    Safe4337ModuleHarness public harness;

    constructor(Safe4337ModuleHarness _harness) {
        harness = _harness;
    }

    function getSafeOp(PackedUserOperation calldata userOp)
        external
        view
        returns (
            bytes memory operationData,
            bytes memory proof,
            uint8 merkleTreeDepth,
            uint48 validAfter,
            uint48 validUntil,
            bytes memory signatures
        )
    {
        return harness.exposed_getSafeOp(userOp);
    }

    function validateSignatures(PackedUserOperation calldata userOp) external view returns (uint256) {
        return harness.exposed_validateSignatures(userOp);
    }

    function checkSignaturesLength(bytes calldata signatures, uint256 threshold) external view returns (bool) {
        return harness.exposed_checkSignaturesLength(signatures, threshold);
    }

    function getOperationHash(PackedUserOperation calldata userOp) external view returns (bytes32) {
        return harness.getOperationHash(userOp);
    }
}

contract MerkleTreeVerificationTest is Test {
    Safe4337ModuleHarness internal module;
    HarnessProxy internal proxy;
    address internal entryPoint;

    // Test signers
    uint256 internal constant SIGNER1_PK = 0xA11CE;
    uint256 internal constant SIGNER2_PK = 0xB0B;
    uint256 internal constant SIGNER3_PK = 0xCA1;

    // Sorted signers and their private keys (set in setUp)
    address[] internal sortedSigners;
    uint256[] internal sortedPKs;

    function setUp() public {
        entryPoint = makeAddr("entryPoint");
        module = new Safe4337ModuleHarness(entryPoint);
        proxy = new HarnessProxy(module);

        address s1 = vm.addr(SIGNER1_PK);
        address s2 = vm.addr(SIGNER2_PK);
        address s3 = vm.addr(SIGNER3_PK);

        // Sort by address ascending
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
    // Section 1: _hashPair
    // =========================================================================

    function test_hashPair_commutative() public view {
        bytes32 a = keccak256("leaf_a");
        bytes32 b = keccak256("leaf_b");
        assertEq(module.exposed_hashPair(a, b), module.exposed_hashPair(b, a));
    }

    function test_hashPair_matchesExpected() public view {
        bytes32 a = keccak256("leaf_a");
        bytes32 b = keccak256("leaf_b");

        bytes32 smaller = a < b ? a : b;
        bytes32 larger = a < b ? b : a;
        bytes32 expected = keccak256(abi.encodePacked(smaller, larger));

        assertEq(module.exposed_hashPair(a, b), expected);
    }

    function test_hashPair_equalInputs() public view {
        bytes32 a = keccak256("same");
        bytes32 expected = keccak256(abi.encodePacked(a, a));
        assertEq(module.exposed_hashPair(a, a), expected);
    }

    function test_hashPair_zeroValue() public view {
        bytes32 zero = bytes32(0);
        bytes32 x = keccak256("nonzero");
        bytes32 expected = keccak256(abi.encodePacked(zero, x));
        assertEq(module.exposed_hashPair(zero, x), expected);
        assertEq(module.exposed_hashPair(x, zero), expected);
    }

    function testFuzz_hashPair_commutative(bytes32 a, bytes32 b) public view {
        assertEq(module.exposed_hashPair(a, b), module.exposed_hashPair(b, a));
    }

    function testFuzz_hashPair_matchesSolidity(bytes32 a, bytes32 b) public view {
        bytes32 smaller = a < b ? a : b;
        bytes32 larger = a < b ? b : a;
        bytes32 expected = keccak256(abi.encodePacked(smaller, larger));
        assertEq(module.exposed_hashPair(a, b), expected);
    }

    // =========================================================================
    // Section 2: _getSafeOp Signature Decoding
    // =========================================================================

    function test_getSafeOp_depth0_decodesCorrectly() public view {
        uint8 depth = 0;
        uint48 validAfter = 100;
        uint48 validUntil = 200;
        bytes memory fakeSig = hex"aabbccdd";

        bytes memory signature = abi.encodePacked(depth, validAfter, validUntil, fakeSig);
        PackedUserOperation memory userOp = _buildUserOp(address(module), signature);

        (
            ,
            ,
            uint8 retDepth,
            uint48 retValidAfter,
            uint48 retValidUntil,
            bytes memory retSignatures
        ) = proxy.getSafeOp(userOp);

        assertEq(retDepth, 0);
        assertEq(retValidAfter, 100);
        assertEq(retValidUntil, 200);
        assertEq(retSignatures, fakeSig);
    }

    function test_getSafeOp_depth1_decodesCorrectly() public view {
        uint8 depth = 1;
        uint48 validAfter = 100;
        uint48 validUntil = 200;

        bytes32 root = keccak256("root");
        bytes32 sibling = keccak256("sibling");
        bytes memory proof = abi.encodePacked(root, sibling);
        bytes memory fakeSig = hex"aabbccdd";

        bytes memory signature = abi.encodePacked(depth, validAfter, validUntil, proof, fakeSig);
        PackedUserOperation memory userOp = _buildUserOp(address(module), signature);

        (
            ,
            bytes memory retProof,
            uint8 retDepth,
            uint48 retValidAfter,
            uint48 retValidUntil,
            bytes memory retSignatures
        ) = proxy.getSafeOp(userOp);

        assertEq(retDepth, 1);
        assertEq(retValidAfter, 100);
        assertEq(retValidUntil, 200);
        assertEq(retProof.length, 64);
        assertEq(retProof, proof);
        assertEq(retSignatures, fakeSig);
    }

    function test_getSafeOp_depth7_worksCorrectly() public view {
        uint8 depth = 7;
        bytes memory proof = new bytes(256); // (7+1) * 32
        bytes memory fakeSig = hex"aa";

        bytes memory signature = abi.encodePacked(depth, uint48(0), uint48(0), proof, fakeSig);
        PackedUserOperation memory userOp = _buildUserOp(address(module), signature);

        (
            ,
            bytes memory retProof,
            uint8 retDepth,
            ,
            ,

        ) = proxy.getSafeOp(userOp);

        assertEq(retDepth, 7);
        assertEq(retProof.length, 256);
    }

    function test_getSafeOp_depth10_maxDepth() public view {
        uint8 depth = 10;
        bytes memory proof = new bytes(352); // (10+1) * 32
        bytes memory fakeSig = hex"aa";

        bytes memory signature = abi.encodePacked(depth, uint48(0), uint48(0), proof, fakeSig);
        PackedUserOperation memory userOp = _buildUserOp(address(module), signature);

        (
            ,
            bytes memory retProof,
            uint8 retDepth,
            ,
            ,

        ) = proxy.getSafeOp(userOp);

        assertEq(retDepth, 10);
        assertEq(retProof.length, 352);
    }

    function test_getSafeOp_depth6_worksCorrectly() public view {
        uint8 depth = 6;
        bytes memory proof = new bytes(224); // (6+1) * 32
        bytes memory fakeSig = hex"aa";

        bytes memory signature = abi.encodePacked(depth, uint48(0), uint48(0), proof, fakeSig);
        PackedUserOperation memory userOp = _buildUserOp(address(module), signature);

        (
            ,
            bytes memory retProof,
            uint8 retDepth,
            ,
            ,

        ) = proxy.getSafeOp(userOp);

        assertEq(retDepth, 6);
        assertEq(retProof.length, 224);
    }

    function test_getSafeOp_depth11_reverts() public {
        uint8 depth = 11;
        bytes memory proof = new bytes(384); // (11+1) * 32
        bytes memory fakeSig = hex"aa";

        bytes memory signature = abi.encodePacked(depth, uint48(0), uint48(0), proof, fakeSig);
        PackedUserOperation memory userOp = _buildUserOp(address(module), signature);

        vm.expectRevert(abi.encodeWithSelector(
            Safe4337MultiChainSignatureModule.MerkleDepthTooLarge.selector, 11
        ));
        proxy.getSafeOp(userOp);
    }

    function test_getSafeOp_depth255_reverts() public {
        bytes memory signature = abi.encodePacked(uint8(255), uint48(0), uint48(0));
        PackedUserOperation memory userOp = _buildUserOp(address(module), signature);

        vm.expectRevert(abi.encodeWithSelector(
            Safe4337MultiChainSignatureModule.MerkleDepthTooLarge.selector, 255
        ));
        proxy.getSafeOp(userOp);
    }

    function test_getSafeOp_truncatedProof_reverts() public {
        uint8 depth = 2;
        // depth=2 expects (2+1)*32 = 96 bytes, provide only 64
        bytes memory shortProof = new bytes(64);

        bytes memory signature = abi.encodePacked(depth, uint48(0), uint48(0), shortProof);
        PackedUserOperation memory userOp = _buildUserOp(address(module), signature);

        vm.expectRevert(abi.encodeWithSelector(
            Safe4337MultiChainSignatureModule.InvalidMerkleProofLength.selector, 96, 64
        ));
        proxy.getSafeOp(userOp);
    }

    // =========================================================================
    // Section 3: EIP-712 Encoding & Domain Separators
    // =========================================================================

    function test_merkleTreeRootDomainSeparatorTypehash() public pure {
        bytes32 expected = keccak256("EIP712Domain(address verifyingContract)");
        assertEq(expected, 0x035aff83d86937d35b32e04f0ddc6ff469290eef2f1b692d8a815c89404d4749);
    }

    function test_merkleTreeRootTypehash() public pure {
        bytes32 expected = keccak256("MerkleTreeRoot(bytes32 merkleTreeRoot)");
        assertEq(expected, 0x63c29879ec9239fe654591f460bc775cd5294088db68113b8065faa722cb0d24);
    }

    function test_safeOpTypehash() public pure {
        bytes32 expected = keccak256(
            "SafeOp(address safe,uint256 nonce,bytes initCode,bytes callData,uint128 verificationGasLimit,uint128 callGasLimit,uint256 preVerificationGas,uint128 maxPriorityFeePerGas,uint128 maxFeePerGas,bytes paymasterAndData,uint48 validAfter,uint48 validUntil,address entryPoint)"
        );
        assertEq(expected, 0xc03dfc11d8b10bf9cf703d558958c8c42777f785d998c62060d85a4f0ef6ea7f);
    }

    function test_domainSeparatorMultiChain_excludesChainId() public {
        bytes32 sep1 = module.domainSeparatorMultiChain();
        vm.chainId(999);
        bytes32 sep2 = module.domainSeparatorMultiChain();
        assertEq(sep1, sep2);
    }

    function test_domainSeparator_includesChainId() public {
        bytes32 sep1 = module.domainSeparator();
        vm.chainId(999);
        bytes32 sep2 = module.domainSeparator();
        assertTrue(sep1 != sep2);
    }

    function test_domainSeparatorMultiChain_matchesExpected() public view {
        bytes32 expected = keccak256(abi.encode(
            keccak256("EIP712Domain(address verifyingContract)"),
            address(module)
        ));
        assertEq(module.domainSeparatorMultiChain(), expected);
    }

    function test_domainSeparator_matchesExpected() public view {
        bytes32 expected = keccak256(abi.encode(
            keccak256("EIP712Domain(uint256 chainId,address verifyingContract)"),
            block.chainid,
            address(module)
        ));
        assertEq(module.domainSeparator(), expected);
    }

    function test_differentModules_differentDomainSeparators() public {
        Safe4337ModuleHarness module2 = new Safe4337ModuleHarness(entryPoint);
        assertTrue(module.domainSeparatorMultiChain() != module2.domainSeparatorMultiChain());
        assertTrue(module.domainSeparator() != module2.domainSeparator());
    }

    // =========================================================================
    // Section 4: Merkle Proof Verification (Happy Path)
    // =========================================================================

    function test_singleChain_validSignature() public {
        (MockSafe safe,, uint256[] memory pks) = _deploySafe(1);

        // depth=0 single chain
        PackedUserOperation memory userOp = _buildModuleUserOp(address(safe), 0);

        // Get operationData for signing
        (bytes memory operationData,,,,,) = proxy.getSafeOp(userOp);
        bytes32 opHash = keccak256(operationData);

        // Sign the opHash directly (single-chain: checkSignatures(keccak256(operationData), ...))
        bytes memory signatures = _signSafe(opHash, pks, 1);

        // Repack with real signatures
        userOp.signature = abi.encodePacked(uint8(0), uint48(0), uint48(0), signatures);

        uint256 validationData = proxy.validateSignatures(userOp);
        assertEq(validationData, 0);
    }

    function test_multiChain_depth1_validProof_leftLeaf() public {
        (MockSafe safe,, uint256[] memory pks) = _deploySafe(1);

        PackedUserOperation memory userOp = _buildModuleUserOp(address(safe), 0);
        (bytes memory operationData,,,,,) = proxy.getSafeOp(userOp);
        bytes32 leaf = keccak256(operationData);

        bytes32 otherLeaf = keccak256("other_chain_op");
        bytes32 root = _hashPair(leaf, otherLeaf);

        // Proof: [root, sibling]
        bytes memory proof = abi.encodePacked(root, otherLeaf);

        // Sign merkle root EIP-712 hash
        bytes32 merkleRootHash = _merkleRootEIP712Hash(root);
        bytes memory signatures = _signSafe(merkleRootHash, pks, 1);

        userOp.signature = abi.encodePacked(uint8(1), uint48(0), uint48(0), proof, signatures);

        uint256 validationData = proxy.validateSignatures(userOp);
        assertEq(validationData, 0);
    }

    function test_multiChain_depth1_validProof_rightLeaf() public {
        (MockSafe safe,, uint256[] memory pks) = _deploySafe(1);

        // Two userOps — validate the "right" one
        PackedUserOperation memory userOpA = _buildModuleUserOp(address(safe), 0);
        (bytes memory opDataA,,,,,) = proxy.getSafeOp(userOpA);
        bytes32 leafA = keccak256(opDataA);

        PackedUserOperation memory userOpB = _buildModuleUserOp(address(safe), 1);
        (bytes memory opDataB,,,,,) = proxy.getSafeOp(userOpB);
        bytes32 leafB = keccak256(opDataB);

        bytes32 root = _hashPair(leafA, leafB);

        // Proof for leafB: [root, leafA]
        bytes memory proof = abi.encodePacked(root, leafA);
        bytes32 merkleRootHash = _merkleRootEIP712Hash(root);
        bytes memory signatures = _signSafe(merkleRootHash, pks, 1);

        userOpB.signature = abi.encodePacked(uint8(1), uint48(0), uint48(0), proof, signatures);

        uint256 validationData = proxy.validateSignatures(userOpB);
        assertEq(validationData, 0);
    }

    function test_multiChain_depth2_validProof_leaf0() public {
        (MockSafe safe,, uint256[] memory pks) = _deploySafe(1);

        PackedUserOperation memory userOp = _buildModuleUserOp(address(safe), 0);
        (bytes memory opData,,,,,) = proxy.getSafeOp(userOp);
        bytes32 leaf0 = keccak256(opData);

        bytes32 leaf1 = keccak256("chain2_op");
        bytes32 leaf2 = keccak256("chain3_op");
        bytes32 leaf3 = keccak256("chain4_op");

        bytes32 node01 = _hashPair(leaf0, leaf1);
        bytes32 node23 = _hashPair(leaf2, leaf3);
        bytes32 root = _hashPair(node01, node23);

        // Proof for leaf0: [root, upper_sibling(node23), bottom_sibling(leaf1)]
        // i=2: proof[2*32] = leaf1, i=1: proof[1*32] = node23
        bytes memory proof = abi.encodePacked(root, node23, leaf1);

        bytes32 merkleRootHash = _merkleRootEIP712Hash(root);
        bytes memory signatures = _signSafe(merkleRootHash, pks, 1);

        userOp.signature = abi.encodePacked(uint8(2), uint48(0), uint48(0), proof, signatures);

        uint256 validationData = proxy.validateSignatures(userOp);
        assertEq(validationData, 0);
    }

    function test_multiChain_depth2_validProof_leaf3() public {
        (MockSafe safe,, uint256[] memory pks) = _deploySafe(1);

        bytes32 leaf0 = keccak256("chain1_op");
        bytes32 leaf1 = keccak256("chain2_op");
        bytes32 leaf2 = keccak256("chain3_op");

        PackedUserOperation memory userOp = _buildModuleUserOp(address(safe), 0);
        (bytes memory opData,,,,,) = proxy.getSafeOp(userOp);
        bytes32 leaf3 = keccak256(opData);

        bytes32 node01 = _hashPair(leaf0, leaf1);
        bytes32 node23 = _hashPair(leaf2, leaf3);
        bytes32 root = _hashPair(node01, node23);

        // Proof for leaf3: [root, node01, leaf2]
        bytes memory proof = abi.encodePacked(root, node01, leaf2);

        bytes32 merkleRootHash = _merkleRootEIP712Hash(root);
        bytes memory signatures = _signSafe(merkleRootHash, pks, 1);

        userOp.signature = abi.encodePacked(uint8(2), uint48(0), uint48(0), proof, signatures);

        uint256 validationData = proxy.validateSignatures(userOp);
        assertEq(validationData, 0);
    }

    /// @dev Build a depth-3 merkle tree and return (root, proof_for_leaf0).
    /// Separated to avoid stack-too-deep in the test function.
    function _buildDepth3Tree(bytes32 leaf0) internal pure returns (bytes32 root, bytes memory proof) {
        bytes32 leaf1 = keccak256("l1");
        bytes32 n01 = _hashPair(leaf0, leaf1);
        bytes32 n23 = _hashPair(keccak256("l2"), keccak256("l3"));
        bytes32 n0123 = _hashPair(n01, n23);
        bytes32 n4567 = _hashPair(
            _hashPair(keccak256("l4"), keccak256("l5")),
            _hashPair(keccak256("l6"), keccak256("l7"))
        );
        root = _hashPair(n0123, n4567);
        // Proof for leaf0: [root, n4567, n23, leaf1]
        proof = abi.encodePacked(root, n4567, n23, leaf1);
    }

    function test_multiChain_depth3_validProof() public {
        (MockSafe safe,, uint256[] memory pks) = _deploySafe(1);

        PackedUserOperation memory userOp = _buildModuleUserOp(address(safe), 0);
        (bytes memory opData,,,,,) = proxy.getSafeOp(userOp);

        (bytes32 root, bytes memory proof) = _buildDepth3Tree(keccak256(opData));

        bytes32 merkleRootHash = _merkleRootEIP712Hash(root);
        bytes memory signatures = _signSafe(merkleRootHash, pks, 1);

        userOp.signature = abi.encodePacked(uint8(3), uint48(0), uint48(0), proof, signatures);

        uint256 validationData = proxy.validateSignatures(userOp);
        assertEq(validationData, 0);
    }

    // =========================================================================
    // Section 5: Merkle Proof Verification (Negative / Security)
    // =========================================================================

    function test_multiChain_wrongSibling_fails() public {
        (MockSafe safe,, uint256[] memory pks) = _deploySafe(1);

        PackedUserOperation memory userOp = _buildModuleUserOp(address(safe), 0);
        (bytes memory opData,,,,,) = proxy.getSafeOp(userOp);
        bytes32 leaf = keccak256(opData);

        bytes32 otherLeaf = keccak256("other");
        bytes32 root = _hashPair(leaf, otherLeaf);

        // WRONG sibling
        bytes32 wrongSibling = keccak256("wrong");
        bytes memory proof = abi.encodePacked(root, wrongSibling);

        bytes32 merkleRootHash = _merkleRootEIP712Hash(root);
        bytes memory signatures = _signSafe(merkleRootHash, pks, 1);

        userOp.signature = abi.encodePacked(uint8(1), uint48(0), uint48(0), proof, signatures);

        uint256 validationData = proxy.validateSignatures(userOp);
        _assertSignatureFailed(validationData);
    }

    function test_multiChain_wrongRoot_fails() public {
        (MockSafe safe,, uint256[] memory pks) = _deploySafe(1);

        PackedUserOperation memory userOp = _buildModuleUserOp(address(safe), 0);
        (bytes memory opData,,,,,) = proxy.getSafeOp(userOp);

        bytes32 otherLeaf = keccak256("other");

        // Use a wrong root — computed from leaf won't match
        bytes32 wrongRoot = keccak256("wrongRoot");
        bytes memory proof = abi.encodePacked(wrongRoot, otherLeaf);

        // Sign wrong root — proof will be valid, but computed root won't match
        bytes32 merkleRootHash = _merkleRootEIP712Hash(wrongRoot);
        bytes memory signatures = _signSafe(merkleRootHash, pks, 1);

        userOp.signature = abi.encodePacked(uint8(1), uint48(0), uint48(0), proof, signatures);

        uint256 validationData = proxy.validateSignatures(userOp);
        _assertSignatureFailed(validationData);
    }

    function test_multiChain_leafSubstitution_fails() public {
        (MockSafe safe,, uint256[] memory pks) = _deploySafe(1);

        PackedUserOperation memory userOpA = _buildModuleUserOp(address(safe), 0);
        PackedUserOperation memory userOpB = _buildModuleUserOp(address(safe), 1);

        (bytes memory opDataA,,,,,) = proxy.getSafeOp(userOpA);
        bytes32 leafA = keccak256(opDataA);

        bytes32 otherLeaf = keccak256("other");
        bytes32 root = _hashPair(leafA, otherLeaf);

        // Valid proof for leafA
        bytes memory proof = abi.encodePacked(root, otherLeaf);
        bytes32 merkleRootHash = _merkleRootEIP712Hash(root);
        bytes memory signatures = _signSafe(merkleRootHash, pks, 1);

        // Attach leafA's proof to userOpB — should fail
        userOpB.signature = abi.encodePacked(uint8(1), uint48(0), uint48(0), proof, signatures);

        uint256 validationData = proxy.validateSignatures(userOpB);
        _assertSignatureFailed(validationData);
    }

    function test_multiChain_invalidSignature_fails() public {
        (MockSafe safe,,) = _deploySafe(1);

        PackedUserOperation memory userOp = _buildModuleUserOp(address(safe), 0);
        (bytes memory opData,,,,,) = proxy.getSafeOp(userOp);
        bytes32 leaf = keccak256(opData);

        bytes32 otherLeaf = keccak256("other");
        bytes32 root = _hashPair(leaf, otherLeaf);
        bytes memory proof = abi.encodePacked(root, otherLeaf);

        // Sign with a non-owner key
        uint256[] memory fakePKs = new uint256[](1);
        fakePKs[0] = 0xDEAD;

        bytes32 merkleRootHash = _merkleRootEIP712Hash(root);
        bytes memory signatures = _signSafe(merkleRootHash, fakePKs, 1);

        userOp.signature = abi.encodePacked(uint8(1), uint48(0), uint48(0), proof, signatures);

        uint256 validationData = proxy.validateSignatures(userOp);
        _assertSignatureFailed(validationData);
    }

    function test_multiChain_nonMemberLeaf_fails() public {
        (MockSafe safe,, uint256[] memory pks) = _deploySafe(1);

        // Build a tree with leafX and leafY (NOT our userOp's leaf)
        bytes32 leafX = keccak256("leafX");
        bytes32 leafY = keccak256("leafY");
        bytes32 root = _hashPair(leafX, leafY);

        // Try to pass this proof for our userOp which produces a different leaf
        PackedUserOperation memory userOp = _buildModuleUserOp(address(safe), 0);
        bytes memory proof = abi.encodePacked(root, leafY);

        bytes32 merkleRootHash = _merkleRootEIP712Hash(root);
        bytes memory signatures = _signSafe(merkleRootHash, pks, 1);

        userOp.signature = abi.encodePacked(uint8(1), uint48(0), uint48(0), proof, signatures);

        uint256 validationData = proxy.validateSignatures(userOp);
        _assertSignatureFailed(validationData);
    }

    function test_singleChain_wrongSignature_fails() public {
        (MockSafe safe,,) = _deploySafe(1);

        PackedUserOperation memory userOp = _buildModuleUserOp(address(safe), 0);

        // Sign with wrong key
        uint256[] memory fakePKs = new uint256[](1);
        fakePKs[0] = 0xDEAD;
        bytes memory signatures = _signSafe(keccak256("wrong"), fakePKs, 1);

        userOp.signature = abi.encodePacked(uint8(0), uint48(0), uint48(0), signatures);

        uint256 validationData = proxy.validateSignatures(userOp);
        _assertSignatureFailed(validationData);
    }

    // =========================================================================
    // Section 6: Multi-sig threshold tests
    // =========================================================================

    function test_multiSig_2of3_validSignature() public {
        (MockSafe safe,, uint256[] memory pks) = _deploySafe(2);

        PackedUserOperation memory userOp = _buildModuleUserOp(address(safe), 0);
        (bytes memory opData,,,,,) = proxy.getSafeOp(userOp);
        bytes32 leaf = keccak256(opData);

        bytes32 otherLeaf = keccak256("other");
        bytes32 root = _hashPair(leaf, otherLeaf);
        bytes memory proof = abi.encodePacked(root, otherLeaf);

        bytes32 merkleRootHash = _merkleRootEIP712Hash(root);
        bytes memory signatures = _signSafe(merkleRootHash, pks, 2);

        userOp.signature = abi.encodePacked(uint8(1), uint48(0), uint48(0), proof, signatures);

        uint256 validationData = proxy.validateSignatures(userOp);
        assertEq(validationData, 0);
    }

    function test_multiSig_3of3_validSignature() public {
        (MockSafe safe,, uint256[] memory pks) = _deploySafe(3);

        PackedUserOperation memory userOp = _buildModuleUserOp(address(safe), 0);
        (bytes memory opData,,,,,) = proxy.getSafeOp(userOp);
        bytes32 otherLeaf = keccak256("other");
        bytes32 root = _hashPair(keccak256(opData), otherLeaf);
        bytes memory proof = abi.encodePacked(root, otherLeaf);

        bytes32 merkleRootHash = _merkleRootEIP712Hash(root);
        bytes memory signatures = _signSafe(merkleRootHash, pks, 3);

        userOp.signature = abi.encodePacked(uint8(1), uint48(0), uint48(0), proof, signatures);

        uint256 validationData = proxy.validateSignatures(userOp);
        assertEq(validationData, 0);
    }

    function test_multiSig_1of3_belowThreshold2_fails() public {
        (MockSafe safe,, uint256[] memory pks) = _deploySafe(2);

        PackedUserOperation memory userOp = _buildModuleUserOp(address(safe), 0);
        (bytes memory opData,,,,,) = proxy.getSafeOp(userOp);
        bytes32 leaf = keccak256(opData);

        bytes32 otherLeaf = keccak256("other");
        bytes32 root = _hashPair(leaf, otherLeaf);
        bytes memory proof = abi.encodePacked(root, otherLeaf);

        bytes32 merkleRootHash = _merkleRootEIP712Hash(root);
        // Only sign with 1 key (threshold is 2)
        bytes memory signatures = _signSafe(merkleRootHash, pks, 1);

        userOp.signature = abi.encodePacked(uint8(1), uint48(0), uint48(0), proof, signatures);

        uint256 validationData = proxy.validateSignatures(userOp);
        _assertSignatureFailed(validationData);
    }

    // =========================================================================
    // Section 7: Cross-Chain Replay Protection
    // =========================================================================

    function test_crossChain_leafIncludesChainId() public {
        (MockSafe safe,,) = _deploySafe(1);

        PackedUserOperation memory userOp = _buildModuleUserOp(address(safe), 0);

        vm.chainId(1);
        (bytes memory opData1,,,,,) = proxy.getSafeOp(userOp);
        bytes32 leaf1 = keccak256(opData1);

        vm.chainId(2);
        (bytes memory opData2,,,,,) = proxy.getSafeOp(userOp);
        bytes32 leaf2 = keccak256(opData2);

        assertTrue(leaf1 != leaf2, "Leaves on different chains must differ");
    }

    function test_crossChain_validProofOnWrongChain_fails() public {
        (MockSafe safe,, uint256[] memory pks) = _deploySafe(1);

        // Build proof on chain 1
        vm.chainId(1);
        PackedUserOperation memory userOp = _buildModuleUserOp(address(safe), 0);
        (bytes memory opData1,,,,,) = proxy.getSafeOp(userOp);
        bytes32 leaf1 = keccak256(opData1);

        bytes32 otherLeaf = keccak256("chain2_op");
        bytes32 root = _hashPair(leaf1, otherLeaf);
        bytes memory proof = abi.encodePacked(root, otherLeaf);

        bytes32 merkleRootHash = _merkleRootEIP712Hash(root);
        bytes memory signatures = _signSafe(merkleRootHash, pks, 1);

        userOp.signature = abi.encodePacked(uint8(1), uint48(0), uint48(0), proof, signatures);

        // Valid on chain 1
        uint256 vd1 = proxy.validateSignatures(userOp);
        assertEq(vd1, 0);

        // Fails on chain 2
        vm.chainId(2);
        uint256 vd2 = proxy.validateSignatures(userOp);
        _assertSignatureFailed(vd2);
    }

    function test_domainSeparatorMultiChain_sameAcrossChains() public {
        vm.chainId(1);
        bytes32 sep1 = module.domainSeparatorMultiChain();

        vm.chainId(137);
        bytes32 sep2 = module.domainSeparatorMultiChain();

        assertEq(sep1, sep2, "Multi-chain domain separator should be chain-agnostic");
    }

    // =========================================================================
    // Section 8: Timestamp / Validation Data Encoding
    // =========================================================================

    function test_validAfter_validUntil_encodedCorrectly() public {
        (MockSafe safe,, uint256[] memory pks) = _deploySafe(1);

        uint48 validAfter = 1000;
        uint48 validUntil = 2000;

        PackedUserOperation memory userOp = _buildModuleUserOpWithTimestamps(address(safe), 0, validAfter, validUntil);

        (bytes memory opData,,,,,) = proxy.getSafeOp(userOp);
        bytes32 opHash = keccak256(opData);

        bytes memory signatures = _signSafe(opHash, pks, 1);
        userOp.signature = abi.encodePacked(uint8(0), validAfter, validUntil, signatures);

        uint256 validationData = proxy.validateSignatures(userOp);

        // packed: validAfter (6 bytes) || validUntil (6 bytes) || authorizer (20 bytes)
        address authorizer = address(uint160(validationData));
        uint48 retValidUntil = uint48(validationData >> 160);
        uint48 retValidAfter = uint48(validationData >> 208);

        assertEq(authorizer, address(0), "Signature should be valid");
        assertEq(retValidAfter, validAfter);
        assertEq(retValidUntil, validUntil);
    }

    function test_multiChain_withTimestamps() public {
        (MockSafe safe,, uint256[] memory pks) = _deploySafe(1);

        uint48 validAfter = 500;
        uint48 validUntil = 1500;

        PackedUserOperation memory userOp = _buildModuleUserOpWithTimestamps(address(safe), 0, validAfter, validUntil);

        (bytes memory opData,,,,,) = proxy.getSafeOp(userOp);
        bytes32 leaf = keccak256(opData);

        bytes32 otherLeaf = keccak256("other");
        bytes32 root = _hashPair(leaf, otherLeaf);
        bytes memory proof = abi.encodePacked(root, otherLeaf);

        bytes32 merkleRootHash = _merkleRootEIP712Hash(root);
        bytes memory signatures = _signSafe(merkleRootHash, pks, 1);

        userOp.signature = abi.encodePacked(uint8(1), validAfter, validUntil, proof, signatures);

        uint256 validationData = proxy.validateSignatures(userOp);

        address authorizer = address(uint160(validationData));
        uint48 retValidUntil = uint48(validationData >> 160);
        uint48 retValidAfter = uint48(validationData >> 208);

        assertEq(authorizer, address(0));
        assertEq(retValidAfter, validAfter);
        assertEq(retValidUntil, validUntil);
    }

    // =========================================================================
    // Section 9: Constructor & Constants
    // =========================================================================

    function test_constructor_zeroEntryPoint_reverts() public {
        vm.expectRevert(Safe4337MultiChainSignatureModule.InvalidEntryPoint.selector);
        new Safe4337ModuleHarness(address(0));
    }

    function test_constructor_setsEntryPoint() public view {
        assertEq(module.SUPPORTED_ENTRYPOINT(), entryPoint);
    }

    function test_maxMerkleDepth_is10() public view {
        assertEq(module.MAX_MERKLE_DEPTH(), 10);
    }

    // =========================================================================
    // Section 10: _checkSignaturesLength
    // =========================================================================

    function test_checkSignaturesLength_validEOA() public view {
        // 1 EOA sig = 65 bytes
        bytes memory sig = new bytes(65);
        assertTrue(proxy.checkSignaturesLength(sig, 1));
    }

    function test_checkSignaturesLength_tooShort() public view {
        bytes memory sig = new bytes(64); // 1 byte short
        assertFalse(proxy.checkSignaturesLength(sig, 1));
    }

    function test_checkSignaturesLength_multipleSigners() public view {
        bytes memory sig = new bytes(65 * 3); // 3 signers
        assertTrue(proxy.checkSignaturesLength(sig, 3));
    }

    function test_checkSignaturesLength_extraBytes_rejected() public view {
        // 1 EOA sig (v=27 at position 64) with 1 extra padding byte
        bytes memory sig = new bytes(66);
        sig[64] = bytes1(uint8(27)); // v = 27, so signatureType != 0 (not a contract sig)
        assertFalse(proxy.checkSignaturesLength(sig, 1));
    }

    function test_checkSignaturesLength_contractSig_accountsForDynamicPart() public view {
        // Signature type 0 (contract signature) with 32-byte dynamic data
        // Static part: 65 bytes. signatureOffset points to dynamic data, signatureLength = 32.
        // maxLength = 65 + 32 (length prefix) + 32 (data) = 129
        // Total sig should be 65 + 32 + 32 = 129
        bytes memory sig = new bytes(129);
        // signatureType at position 0x40 (64) = 0 (contract sig)
        sig[64] = bytes1(0x00);
        // signatureOffset at position 0x20..0x3F: points to byte 65 (after static part)
        sig[63] = bytes1(uint8(65));
        // signatureLength at byte 65..96: length = 32
        sig[96] = bytes1(uint8(32));
        assertTrue(proxy.checkSignaturesLength(sig, 1));
    }

    // =========================================================================
    // Section 11: Additional Edge Cases
    // =========================================================================

    /// @notice Signature shorter than the 13-byte header should revert (OOB slice).
    function test_getSafeOp_signatureTooShort_reverts() public {
        // Only 5 bytes — not enough for depth(1) + validAfter(6) + validUntil(6)
        bytes memory signature = hex"0000000000";
        PackedUserOperation memory userOp = _buildUserOp(address(module), signature);
        vm.expectRevert();
        proxy.getSafeOp(userOp);
    }

    /// @notice Even with valid ECDSA signature, padded extra bytes cause
    /// _checkSignaturesLength to return false, so validation must fail.
    function test_validSigButPaddedExtraBytes_fails() public {
        (MockSafe safe,, uint256[] memory pks) = _deploySafe(1);

        PackedUserOperation memory userOp = _buildModuleUserOp(address(safe), 0);
        (bytes memory opData,,,,,) = proxy.getSafeOp(userOp);
        bytes32 opHash = keccak256(opData);

        bytes memory signatures = _signSafe(opHash, pks, 1);
        // Append 1 extra byte — _checkSignaturesLength should reject
        signatures = abi.encodePacked(signatures, uint8(0xff));

        userOp.signature = abi.encodePacked(uint8(0), uint48(0), uint48(0), signatures);

        uint256 validationData = proxy.validateSignatures(userOp);
        _assertSignatureFailed(validationData);
    }

    /// @notice Single-chain signature replayed with depth=1 must fail.
    /// The multi-chain path signs keccak256(merkleRootHashData), not keccak256(operationData).
    function test_modeConfusion_singleToMultiChain_fails() public {
        (MockSafe safe,, uint256[] memory pks) = _deploySafe(1);

        PackedUserOperation memory userOp = _buildModuleUserOp(address(safe), 0);
        (bytes memory opData,,,,,) = proxy.getSafeOp(userOp);
        bytes32 opHash = keccak256(opData);

        // Sign the single-chain hash
        bytes memory signatures = _signSafe(opHash, pks, 1);

        // Try to submit with depth=1 — the signature is checked against the merkle root EIP-712 hash
        bytes32 fakeRoot = keccak256("fakeRoot");
        bytes32 fakeSibling = keccak256("fakeSibling");
        bytes memory proof = abi.encodePacked(fakeRoot, fakeSibling);

        userOp.signature = abi.encodePacked(uint8(1), uint48(0), uint48(0), proof, signatures);

        uint256 validationData = proxy.validateSignatures(userOp);
        _assertSignatureFailed(validationData);
    }

    /// @notice Multi-chain root signature replayed with depth=0 must fail.
    /// The single-chain path checks signature against keccak256(operationData).
    function test_modeConfusion_multiToSingleChain_fails() public {
        (MockSafe safe,, uint256[] memory pks) = _deploySafe(1);

        PackedUserOperation memory userOp = _buildModuleUserOp(address(safe), 0);
        (bytes memory opData,,,,,) = proxy.getSafeOp(userOp);
        bytes32 leaf = keccak256(opData);

        bytes32 otherLeaf = keccak256("other");
        bytes32 root = _hashPair(leaf, otherLeaf);

        // Sign the merkle root EIP-712 hash
        bytes32 merkleRootHash = _merkleRootEIP712Hash(root);
        bytes memory signatures = _signSafe(merkleRootHash, pks, 1);

        // Submit with depth=0 — signature is checked against keccak256(operationData), not merkle root
        userOp.signature = abi.encodePacked(uint8(0), uint48(0), uint48(0), signatures);

        uint256 validationData = proxy.validateSignatures(userOp);
        _assertSignatureFailed(validationData);
    }

    /// @notice getOperationHash returns the leaf hash used in both single-chain and multi-chain paths.
    function test_getOperationHash_matchesLeaf() public {
        (MockSafe safe,,) = _deploySafe(1);

        PackedUserOperation memory userOp = _buildModuleUserOp(address(safe), 0);
        (bytes memory opData,,,,,) = proxy.getSafeOp(userOp);
        bytes32 expectedHash = keccak256(opData);

        bytes32 opHash = proxy.getOperationHash(userOp);
        assertEq(opHash, expectedHash);
    }

    /// @notice Changing initCode changes the leaf hash (operationData covers initCode).
    function test_initCode_affectsLeaf() public {
        (MockSafe safe,,) = _deploySafe(1);

        bytes memory dummySig = abi.encodePacked(uint8(0), uint48(0), uint48(0));

        PackedUserOperation memory userOp1 = PackedUserOperation({
            sender: address(safe),
            nonce: 0,
            initCode: "",
            callData: abi.encodeWithSelector(module.executeUserOp.selector, address(0), 0, "", 0),
            accountGasLimits: bytes32(uint256(100000) << 128 | uint256(100000)),
            preVerificationGas: 21000,
            gasFees: bytes32(uint256(1 gwei) << 128 | uint256(1 gwei)),
            paymasterAndData: "",
            signature: dummySig
        });

        PackedUserOperation memory userOp2 = PackedUserOperation({
            sender: address(safe),
            nonce: 0,
            initCode: hex"deadbeef",
            callData: abi.encodeWithSelector(module.executeUserOp.selector, address(0), 0, "", 0),
            accountGasLimits: bytes32(uint256(100000) << 128 | uint256(100000)),
            preVerificationGas: 21000,
            gasFees: bytes32(uint256(1 gwei) << 128 | uint256(1 gwei)),
            paymasterAndData: "",
            signature: dummySig
        });

        bytes32 hash1 = proxy.getOperationHash(userOp1);
        bytes32 hash2 = proxy.getOperationHash(userOp2);
        assertTrue(hash1 != hash2, "Different initCode must produce different hashes");
    }

    /// @notice Changing paymasterAndData changes the leaf hash.
    function test_paymasterAndData_affectsLeaf() public {
        (MockSafe safe,,) = _deploySafe(1);

        bytes memory dummySig = abi.encodePacked(uint8(0), uint48(0), uint48(0));

        PackedUserOperation memory userOp1 = PackedUserOperation({
            sender: address(safe),
            nonce: 0,
            initCode: "",
            callData: abi.encodeWithSelector(module.executeUserOp.selector, address(0), 0, "", 0),
            accountGasLimits: bytes32(uint256(100000) << 128 | uint256(100000)),
            preVerificationGas: 21000,
            gasFees: bytes32(uint256(1 gwei) << 128 | uint256(1 gwei)),
            paymasterAndData: "",
            signature: dummySig
        });

        PackedUserOperation memory userOp2 = PackedUserOperation({
            sender: address(safe),
            nonce: 0,
            initCode: "",
            callData: abi.encodeWithSelector(module.executeUserOp.selector, address(0), 0, "", 0),
            accountGasLimits: bytes32(uint256(100000) << 128 | uint256(100000)),
            preVerificationGas: 21000,
            gasFees: bytes32(uint256(1 gwei) << 128 | uint256(1 gwei)),
            paymasterAndData: hex"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            signature: dummySig
        });

        bytes32 hash1 = proxy.getOperationHash(userOp1);
        bytes32 hash2 = proxy.getOperationHash(userOp2);
        assertTrue(hash1 != hash2, "Different paymasterAndData must produce different hashes");
    }

    /// @notice Unbalanced tree: 3 leaves at depth 2 (one leaf duplicated to fill).
    function test_multiChain_depth2_unbalanced3Leaves() public {
        (MockSafe safe,, uint256[] memory pks) = _deploySafe(1);

        PackedUserOperation memory userOp = _buildModuleUserOp(address(safe), 0);
        (bytes memory opData,,,,,) = proxy.getSafeOp(userOp);
        bytes32 leaf0 = keccak256(opData);

        bytes32 leaf1 = keccak256("chain2_op");
        bytes32 leaf2 = keccak256("chain3_op");
        // Duplicate leaf2 to fill the tree
        bytes32 leaf3 = leaf2;

        bytes32 node01 = _hashPair(leaf0, leaf1);
        bytes32 node23 = _hashPair(leaf2, leaf3);
        bytes32 root = _hashPair(node01, node23);

        bytes memory proof = abi.encodePacked(root, node23, leaf1);

        bytes32 merkleRootHash = _merkleRootEIP712Hash(root);
        bytes memory signatures = _signSafe(merkleRootHash, pks, 1);

        userOp.signature = abi.encodePacked(uint8(2), uint48(0), uint48(0), proof, signatures);

        uint256 validationData = proxy.validateSignatures(userOp);
        assertEq(validationData, 0);
    }

    /// @notice Depth-1 tree where both leaves are identical (the userOp itself appears twice).
    function test_multiChain_depth1_identicalLeaves() public {
        (MockSafe safe,, uint256[] memory pks) = _deploySafe(1);

        PackedUserOperation memory userOp = _buildModuleUserOp(address(safe), 0);
        (bytes memory opData,,,,,) = proxy.getSafeOp(userOp);
        bytes32 leaf = keccak256(opData);

        // Tree with two identical leaves
        bytes32 root = _hashPair(leaf, leaf);
        bytes memory proof = abi.encodePacked(root, leaf);

        bytes32 merkleRootHash = _merkleRootEIP712Hash(root);
        bytes memory signatures = _signSafe(merkleRootHash, pks, 1);

        userOp.signature = abi.encodePacked(uint8(1), uint48(0), uint48(0), proof, signatures);

        uint256 validationData = proxy.validateSignatures(userOp);
        assertEq(validationData, 0);
    }

    /// @notice Changing callData changes the leaf hash.
    function test_callData_affectsLeaf() public {
        (MockSafe safe,,) = _deploySafe(1);

        bytes memory dummySig = abi.encodePacked(uint8(0), uint48(0), uint48(0));

        PackedUserOperation memory userOp1 = PackedUserOperation({
            sender: address(safe),
            nonce: 0,
            initCode: "",
            callData: abi.encodeWithSelector(module.executeUserOp.selector, address(0), 0, "", 0),
            accountGasLimits: bytes32(uint256(100000) << 128 | uint256(100000)),
            preVerificationGas: 21000,
            gasFees: bytes32(uint256(1 gwei) << 128 | uint256(1 gwei)),
            paymasterAndData: "",
            signature: dummySig
        });

        PackedUserOperation memory userOp2 = PackedUserOperation({
            sender: address(safe),
            nonce: 0,
            initCode: "",
            callData: abi.encodeWithSelector(module.executeUserOp.selector, address(1), 1 ether, hex"cafe", 0),
            accountGasLimits: bytes32(uint256(100000) << 128 | uint256(100000)),
            preVerificationGas: 21000,
            gasFees: bytes32(uint256(1 gwei) << 128 | uint256(1 gwei)),
            paymasterAndData: "",
            signature: dummySig
        });

        bytes32 hash1 = proxy.getOperationHash(userOp1);
        bytes32 hash2 = proxy.getOperationHash(userOp2);
        assertTrue(hash1 != hash2, "Different callData must produce different hashes");
    }

    /// @notice Nonce changes the leaf hash.
    function test_nonce_affectsLeaf() public {
        (MockSafe safe,,) = _deploySafe(1);

        PackedUserOperation memory userOp1 = _buildModuleUserOp(address(safe), 0);
        PackedUserOperation memory userOp2 = _buildModuleUserOp(address(safe), 1);

        bytes32 hash1 = proxy.getOperationHash(userOp1);
        bytes32 hash2 = proxy.getOperationHash(userOp2);
        assertTrue(hash1 != hash2, "Different nonce must produce different hashes");
    }

    /// @notice Gas params change the leaf hash.
    function test_gasParams_affectLeaf() public {
        (MockSafe safe,,) = _deploySafe(1);

        bytes memory dummySig = abi.encodePacked(uint8(0), uint48(0), uint48(0));

        PackedUserOperation memory userOp1 = PackedUserOperation({
            sender: address(safe),
            nonce: 0,
            initCode: "",
            callData: abi.encodeWithSelector(module.executeUserOp.selector, address(0), 0, "", 0),
            accountGasLimits: bytes32(uint256(100000) << 128 | uint256(100000)),
            preVerificationGas: 21000,
            gasFees: bytes32(uint256(1 gwei) << 128 | uint256(1 gwei)),
            paymasterAndData: "",
            signature: dummySig
        });

        PackedUserOperation memory userOp2 = PackedUserOperation({
            sender: address(safe),
            nonce: 0,
            initCode: "",
            callData: abi.encodeWithSelector(module.executeUserOp.selector, address(0), 0, "", 0),
            accountGasLimits: bytes32(uint256(200000) << 128 | uint256(200000)),
            preVerificationGas: 42000,
            gasFees: bytes32(uint256(2 gwei) << 128 | uint256(2 gwei)),
            paymasterAndData: "",
            signature: dummySig
        });

        bytes32 hash1 = proxy.getOperationHash(userOp1);
        bytes32 hash2 = proxy.getOperationHash(userOp2);
        assertTrue(hash1 != hash2, "Different gas params must produce different hashes");
    }

    /// @notice Empty signatures with depth > 0 — _checkSignaturesLength returns false,
    /// then checkSignatures also fails. Must return SIG_VALIDATION_FAILED.
    function test_multiChain_emptySignatures_fails() public {
        (MockSafe safe,,) = _deploySafe(1);

        PackedUserOperation memory userOp = _buildModuleUserOp(address(safe), 0);
        (bytes memory opData,,,,,) = proxy.getSafeOp(userOp);
        bytes32 leaf = keccak256(opData);

        bytes32 otherLeaf = keccak256("other");
        bytes32 root = _hashPair(leaf, otherLeaf);
        bytes memory proof = abi.encodePacked(root, otherLeaf);

        // No signatures at all
        userOp.signature = abi.encodePacked(uint8(1), uint48(0), uint48(0), proof);

        uint256 validationData = proxy.validateSignatures(userOp);
        _assertSignatureFailed(validationData);
    }

    /// @notice entryPoint address is baked into the leaf hash.
    function test_entryPoint_affectsLeaf() public {
        (MockSafe safe,,) = _deploySafe(1);

        Safe4337ModuleHarness module2 = new Safe4337ModuleHarness(address(0xBEEF));
        HarnessProxy proxy2 = new HarnessProxy(module2);
        safe.setFallbackHandler(address(module2));

        PackedUserOperation memory userOp = _buildModuleUserOp(address(safe), 0);

        safe.setFallbackHandler(address(module));
        bytes32 hash1 = proxy.getOperationHash(userOp);

        safe.setFallbackHandler(address(module2));
        bytes32 hash2 = proxy2.getOperationHash(userOp);

        assertTrue(hash1 != hash2, "Different entryPoint must produce different hashes");
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

    function _buildUserOp(address sender, bytes memory signature) internal view returns (PackedUserOperation memory) {
        return PackedUserOperation({
            sender: sender,
            nonce: 0,
            initCode: "",
            callData: abi.encodeWithSelector(module.executeUserOp.selector, address(0), 0, "", 0),
            accountGasLimits: bytes32(uint256(100000) << 128 | uint256(100000)),
            preVerificationGas: 21000,
            gasFees: bytes32(uint256(1 gwei) << 128 | uint256(1 gwei)),
            paymasterAndData: "",
            signature: signature
        });
    }

    function _buildModuleUserOp(address safe, uint256 nonce) internal view returns (PackedUserOperation memory) {
        // Dummy signature for initial getSafeOp call — will be overwritten
        bytes memory dummySig = abi.encodePacked(uint8(0), uint48(0), uint48(0));
        return PackedUserOperation({
            sender: safe,
            nonce: nonce,
            initCode: "",
            callData: abi.encodeWithSelector(module.executeUserOp.selector, address(0), 0, "", 0),
            accountGasLimits: bytes32(uint256(100000) << 128 | uint256(100000)),
            preVerificationGas: 21000,
            gasFees: bytes32(uint256(1 gwei) << 128 | uint256(1 gwei)),
            paymasterAndData: "",
            signature: dummySig
        });
    }

    function _buildModuleUserOpWithTimestamps(
        address safe,
        uint256 nonce,
        uint48 validAfter,
        uint48 validUntil
    ) internal view returns (PackedUserOperation memory) {
        bytes memory dummySig = abi.encodePacked(uint8(0), validAfter, validUntil);
        return PackedUserOperation({
            sender: safe,
            nonce: nonce,
            initCode: "",
            callData: abi.encodeWithSelector(module.executeUserOp.selector, address(0), 0, "", 0),
            accountGasLimits: bytes32(uint256(100000) << 128 | uint256(100000)),
            preVerificationGas: 21000,
            gasFees: bytes32(uint256(1 gwei) << 128 | uint256(1 gwei)),
            paymasterAndData: "",
            signature: dummySig
        });
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

    function _signSafe(bytes32 hash, uint256[] memory pks, uint256 count) internal view returns (bytes memory signatures) {
        signatures = "";
        for (uint256 i = 0; i < count; i++) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(pks[i], hash);
            signatures = abi.encodePacked(signatures, r, s, v);
        }
    }

    function _assertSignatureFailed(uint256 validationData) internal pure {
        // authorizer = 1 means SIG_VALIDATION_FAILED in ERC-4337
        address authorizer = address(uint160(validationData));
        assertEq(authorizer, address(1), "Expected signature validation failure");
    }
}
