// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {Safe4337ModuleHarness} from "./Safe4337ModuleHarness.sol";
import {MockSafe} from "./MockSafe.sol";
import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {Safe4337MultiChainSignatureModule} from "../Safe4337MultiChainSignatureModule.sol";
import {IAccount} from "@account-abstraction/contracts/interfaces/IAccount.sol";
import {UserOperationLib} from "@account-abstraction/contracts/core/UserOperationLib.sol";

// =========================================================================
// Helper Contracts
// =========================================================================

contract RevertingTarget {
    error CustomError(string reason);

    function alwaysReverts() external pure {
        revert("intentional revert");
    }

    function revertsWithCustomError() external pure {
        revert CustomError("custom error");
    }
}

contract SuccessTarget {
    uint256 public value;

    function setValue(uint256 _value) external {
        value = _value;
    }

    receive() external payable {}
}

/**
 * @dev Simulates an EntryPoint calling through the Safe's fallback handler.
 *      The Safe's fallback appends msg.sender (this contract) per ERC-2771.
 */
contract EntryPointSimulator {
    function simulateValidateUserOp(
        address safe,
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external returns (uint256) {
        (bool success, bytes memory retData) = safe.call(
            abi.encodeWithSelector(
                IAccount.validateUserOp.selector,
                userOp,
                userOpHash,
                missingAccountFunds
            )
        );
        require(success, string(retData));
        return abi.decode(retData, (uint256));
    }

    function simulateValidateUserOpRaw(
        address safe,
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external returns (bool success, bytes memory retData) {
        (success, retData) = safe.call(
            abi.encodeWithSelector(
                IAccount.validateUserOp.selector,
                userOp,
                userOpHash,
                missingAccountFunds
            )
        );
    }

    function simulateExecuteUserOp(
        address safe,
        address to,
        uint256 value,
        bytes calldata data,
        uint8 operation
    ) external returns (bool success, bytes memory retData) {
        (success, retData) = safe.call(
            abi.encodeWithSelector(
                Safe4337MultiChainSignatureModule.executeUserOp.selector,
                to,
                value,
                data,
                operation
            )
        );
    }

    function simulateExecuteUserOpWithErrorString(
        address safe,
        address to,
        uint256 value,
        bytes calldata data,
        uint8 operation
    ) external returns (bool success, bytes memory retData) {
        (success, retData) = safe.call(
            abi.encodeWithSelector(
                Safe4337MultiChainSignatureModule.executeUserOpWithErrorString.selector,
                to,
                value,
                data,
                operation
            )
        );
    }

    receive() external payable {}
}

/**
 * @dev Proxy that converts memory UserOps to calldata for harness calls.
 */
contract HarnessProxy2 {
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

// =========================================================================
// Main Test Contract
// =========================================================================

contract ComprehensiveModuleTest is Test {
    Safe4337ModuleHarness internal module;
    HarnessProxy2 internal proxy;
    EntryPointSimulator internal entryPointSim;
    address internal entryPoint;

    uint256 internal constant SIGNER1_PK = 0xA11CE;
    uint256 internal constant SIGNER2_PK = 0xB0B;
    uint256 internal constant SIGNER3_PK = 0xCA1;

    address[] internal sortedSigners;
    uint256[] internal sortedPKs;

    function setUp() public {
        entryPointSim = new EntryPointSimulator();
        entryPoint = address(entryPointSim);
        module = new Safe4337ModuleHarness(entryPoint);
        proxy = new HarnessProxy2(module);

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
    // Section 12: validateUserOp Access Control
    // =========================================================================

    /// @notice Calling validateUserOp from a non-entry-point should revert UnsupportedEntryPoint.
    function test_validateUserOp_unsupportedEntryPoint() public {
        (MockSafe safe,, uint256[] memory pks) = _deploySafe(1);

        PackedUserOperation memory userOp = _buildModuleUserOp(address(safe), 0);
        (bytes memory opData,,,,,) = proxy.getSafeOp(userOp);
        bytes32 opHash = keccak256(opData);
        bytes memory signatures = _signSafe(opHash, pks, 1);
        userOp.signature = abi.encodePacked(uint8(0), uint48(0), uint48(0), signatures);

        // Call through Safe from a non-entrypoint address
        address fakeEntryPoint = makeAddr("fakeEntryPoint");
        bytes memory callData = abi.encodeWithSelector(
            IAccount.validateUserOp.selector,
            userOp,
            bytes32(0),
            uint256(0)
        );
        vm.prank(fakeEntryPoint);
        (bool success, bytes memory retData) = address(safe).call(callData);
        assertFalse(success, "Should revert for non-entry-point caller");
        // Verify it's UnsupportedEntryPoint error
        bytes4 errorSelector = bytes4(retData);
        assertEq(errorSelector, Safe4337MultiChainSignatureModule.UnsupportedEntryPoint.selector);
    }

    /// @notice userOp.sender != msg.sender (Safe) should revert InvalidCaller.
    function test_validateUserOp_invalidCaller() public {
        (MockSafe safe,, uint256[] memory pks) = _deploySafe(1);

        // Set userOp.sender to a different address than the safe
        address wrongSender = makeAddr("wrongSender");
        PackedUserOperation memory userOp = _buildModuleUserOp(wrongSender, 0);
        (bytes memory opData,,,,,) = proxy.getSafeOp(userOp);
        bytes32 opHash = keccak256(opData);
        bytes memory signatures = _signSafe(opHash, pks, 1);
        userOp.signature = abi.encodePacked(uint8(0), uint48(0), uint48(0), signatures);

        (bool success, bytes memory retData) = entryPointSim.simulateValidateUserOpRaw(
            address(safe), userOp, bytes32(0), 0
        );
        assertFalse(success, "Should revert for wrong sender");
        bytes4 errorSelector = bytes4(retData);
        assertEq(errorSelector, Safe4337MultiChainSignatureModule.InvalidCaller.selector);
    }

    /// @notice callData with an unsupported function selector should revert.
    function test_validateUserOp_unsupportedExecutionFunction() public {
        (MockSafe safe,,) = _deploySafe(1);

        bytes memory dummySig = abi.encodePacked(uint8(0), uint48(0), uint48(0), new bytes(65));
        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(safe),
            nonce: 0,
            initCode: "",
            callData: abi.encodeWithSelector(bytes4(0xdeadbeef), address(0), 0, "", 0),
            accountGasLimits: bytes32(uint256(100000) << 128 | uint256(100000)),
            preVerificationGas: 21000,
            gasFees: bytes32(uint256(1 gwei) << 128 | uint256(1 gwei)),
            paymasterAndData: "",
            signature: dummySig
        });

        (bool success, bytes memory retData) = entryPointSim.simulateValidateUserOpRaw(
            address(safe), userOp, bytes32(0), 0
        );
        assertFalse(success, "Should revert for unsupported selector");
        bytes4 errorSelector = bytes4(retData);
        assertEq(errorSelector, Safe4337MultiChainSignatureModule.UnsupportedExecutionFunction.selector);
    }

    /// @notice executeUserOpWithErrorString selector should be accepted.
    function test_validateUserOp_acceptsExecuteUserOpWithErrorString() public {
        (MockSafe safe,, uint256[] memory pks) = _deploySafe(1);

        bytes memory dummySig = abi.encodePacked(uint8(0), uint48(0), uint48(0));
        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(safe),
            nonce: 0,
            initCode: "",
            callData: abi.encodeWithSelector(module.executeUserOpWithErrorString.selector, address(0), 0, "", 0),
            accountGasLimits: bytes32(uint256(100000) << 128 | uint256(100000)),
            preVerificationGas: 21000,
            gasFees: bytes32(uint256(1 gwei) << 128 | uint256(1 gwei)),
            paymasterAndData: "",
            signature: dummySig
        });

        // Get real operation data and sign it
        (bytes memory opData,,,,,) = proxy.getSafeOp(userOp);
        bytes32 opHash = keccak256(opData);
        bytes memory signatures = _signSafe(opHash, pks, 1);
        userOp.signature = abi.encodePacked(uint8(0), uint48(0), uint48(0), signatures);

        uint256 validationData = entryPointSim.simulateValidateUserOp(
            address(safe), userOp, bytes32(0), 0
        );
        assertEq(validationData, 0, "Should accept executeUserOpWithErrorString selector");
    }

    // =========================================================================
    // Section 13: validateUserOp Integration (full flow)
    // =========================================================================

    /// @notice Full integration: valid single-chain signature through entry point.
    function test_validateUserOp_fullIntegration_singleChain() public {
        (MockSafe safe,, uint256[] memory pks) = _deploySafe(1);

        PackedUserOperation memory userOp = _buildModuleUserOp(address(safe), 0);
        (bytes memory opData,,,,,) = proxy.getSafeOp(userOp);
        bytes32 opHash = keccak256(opData);
        bytes memory signatures = _signSafe(opHash, pks, 1);
        userOp.signature = abi.encodePacked(uint8(0), uint48(0), uint48(0), signatures);

        uint256 validationData = entryPointSim.simulateValidateUserOp(
            address(safe), userOp, bytes32(0), 0
        );
        assertEq(validationData, 0);
    }

    /// @notice Full integration: valid multi-chain signature through entry point.
    function test_validateUserOp_fullIntegration_multiChain() public {
        (MockSafe safe,, uint256[] memory pks) = _deploySafe(1);

        PackedUserOperation memory userOp = _buildModuleUserOp(address(safe), 0);
        (bytes memory opData,,,,,) = proxy.getSafeOp(userOp);
        bytes32 leaf = keccak256(opData);

        bytes32 otherLeaf = keccak256("other_chain_op");
        bytes32 root = _hashPair(leaf, otherLeaf);
        bytes memory proof = abi.encodePacked(root, otherLeaf);

        bytes32 merkleRootHash = _merkleRootEIP712Hash(root);
        bytes memory signatures = _signSafe(merkleRootHash, pks, 1);
        userOp.signature = abi.encodePacked(uint8(1), uint48(0), uint48(0), proof, signatures);

        uint256 validationData = entryPointSim.simulateValidateUserOp(
            address(safe), userOp, bytes32(0), 0
        );
        assertEq(validationData, 0);
    }

    /// @notice missingAccountFunds > 0 should pay the entry point.
    function test_validateUserOp_paysPrefund() public {
        (MockSafe safe,, uint256[] memory pks) = _deploySafe(1);
        uint256 prefund = 0.01 ether;
        vm.deal(address(safe), prefund);

        PackedUserOperation memory userOp = _buildModuleUserOp(address(safe), 0);
        (bytes memory opData,,,,,) = proxy.getSafeOp(userOp);
        bytes32 opHash = keccak256(opData);
        bytes memory signatures = _signSafe(opHash, pks, 1);
        userOp.signature = abi.encodePacked(uint8(0), uint48(0), uint48(0), signatures);

        uint256 epBalanceBefore = address(entryPointSim).balance;
        entryPointSim.simulateValidateUserOp(address(safe), userOp, bytes32(0), prefund);
        uint256 epBalanceAfter = address(entryPointSim).balance;

        assertEq(epBalanceAfter - epBalanceBefore, prefund, "Entry point should receive prefund");
    }

    /// @notice missingAccountFunds == 0 should not transfer ETH.
    function test_validateUserOp_zeroPrefund_noPayment() public {
        (MockSafe safe,, uint256[] memory pks) = _deploySafe(1);
        vm.deal(address(safe), 1 ether);

        PackedUserOperation memory userOp = _buildModuleUserOp(address(safe), 0);
        (bytes memory opData,,,,,) = proxy.getSafeOp(userOp);
        bytes32 opHash = keccak256(opData);
        bytes memory signatures = _signSafe(opHash, pks, 1);
        userOp.signature = abi.encodePacked(uint8(0), uint48(0), uint48(0), signatures);

        uint256 safeBalanceBefore = address(safe).balance;
        entryPointSim.simulateValidateUserOp(address(safe), userOp, bytes32(0), 0);
        uint256 safeBalanceAfter = address(safe).balance;

        assertEq(safeBalanceBefore, safeBalanceAfter, "Safe balance should not change with zero prefund");
    }

    /// @notice Invalid signature through full validateUserOp flow still returns SIG_VALIDATION_FAILED (no revert).
    function test_validateUserOp_invalidSig_returnsFailure() public {
        (MockSafe safe,,) = _deploySafe(1);

        PackedUserOperation memory userOp = _buildModuleUserOp(address(safe), 0);
        // Sign with a wrong key
        uint256[] memory fakePKs = new uint256[](1);
        fakePKs[0] = 0xDEAD;
        bytes memory signatures = _signSafe(keccak256("wrong"), fakePKs, 1);
        userOp.signature = abi.encodePacked(uint8(0), uint48(0), uint48(0), signatures);

        uint256 validationData = entryPointSim.simulateValidateUserOp(
            address(safe), userOp, bytes32(0), 0
        );
        _assertSignatureFailed(validationData);
    }

    /// @notice Timestamps are correctly propagated through validateUserOp.
    function test_validateUserOp_timestampsPropagated() public {
        (MockSafe safe,, uint256[] memory pks) = _deploySafe(1);

        uint48 validAfter = 5000;
        uint48 validUntil = 10000;

        PackedUserOperation memory userOp = _buildModuleUserOpWithTimestamps(address(safe), 0, validAfter, validUntil);
        (bytes memory opData,,,,,) = proxy.getSafeOp(userOp);
        bytes32 opHash = keccak256(opData);
        bytes memory signatures = _signSafe(opHash, pks, 1);
        userOp.signature = abi.encodePacked(uint8(0), validAfter, validUntil, signatures);

        uint256 validationData = entryPointSim.simulateValidateUserOp(
            address(safe), userOp, bytes32(0), 0
        );

        address authorizer = address(uint160(validationData));
        uint48 retValidUntil = uint48(validationData >> 160);
        uint48 retValidAfter = uint48(validationData >> 208);

        assertEq(authorizer, address(0));
        assertEq(retValidAfter, validAfter);
        assertEq(retValidUntil, validUntil);
    }

    // =========================================================================
    // Section 14: executeUserOp
    // =========================================================================

    /// @notice Successful execution through executeUserOp.
    function test_executeUserOp_success() public {
        (MockSafe safe,,) = _deploySafe(1);
        SuccessTarget target = new SuccessTarget();

        bytes memory execData = abi.encodeWithSelector(SuccessTarget.setValue.selector, 42);
        (bool success,) = entryPointSim.simulateExecuteUserOp(
            address(safe), address(target), 0, execData, 0
        );
        assertTrue(success, "executeUserOp should succeed");
        assertEq(target.value(), 42, "Target value should be set");
    }

    /// @notice executeUserOp reverts with ExecutionFailed when inner call fails.
    function test_executeUserOp_executionFailed() public {
        (MockSafe safe,,) = _deploySafe(1);
        RevertingTarget target = new RevertingTarget();

        bytes memory execData = abi.encodeWithSelector(RevertingTarget.alwaysReverts.selector);
        (bool success, bytes memory retData) = entryPointSim.simulateExecuteUserOp(
            address(safe), address(target), 0, execData, 0
        );
        assertFalse(success, "Should revert");
        bytes4 errorSelector = bytes4(retData);
        assertEq(errorSelector, Safe4337MultiChainSignatureModule.ExecutionFailed.selector);
    }

    /// @notice executeUserOp from non-entry-point reverts UnsupportedEntryPoint.
    function test_executeUserOp_unsupportedEntryPoint() public {
        (MockSafe safe,,) = _deploySafe(1);

        address fakeEP = makeAddr("fakeEP");
        vm.prank(fakeEP);
        (bool success, bytes memory retData) = address(safe).call(
            abi.encodeWithSelector(
                Safe4337MultiChainSignatureModule.executeUserOp.selector,
                address(0), 0, "", 0
            )
        );
        assertFalse(success);
        bytes4 errorSelector = bytes4(retData);
        assertEq(errorSelector, Safe4337MultiChainSignatureModule.UnsupportedEntryPoint.selector);
    }

    /// @notice executeUserOp can send ETH.
    function test_executeUserOp_sendsEth() public {
        (MockSafe safe,,) = _deploySafe(1);
        SuccessTarget target = new SuccessTarget();
        vm.deal(address(safe), 1 ether);

        uint256 sendAmount = 0.5 ether;
        (bool success,) = entryPointSim.simulateExecuteUserOp(
            address(safe), address(target), sendAmount, "", 0
        );
        assertTrue(success);
        assertEq(address(target).balance, sendAmount);
    }

    // =========================================================================
    // Section 15: executeUserOpWithErrorString
    // =========================================================================

    /// @notice Successful execution through executeUserOpWithErrorString.
    function test_executeUserOpWithErrorString_success() public {
        (MockSafe safe,,) = _deploySafe(1);
        SuccessTarget target = new SuccessTarget();

        bytes memory execData = abi.encodeWithSelector(SuccessTarget.setValue.selector, 99);
        (bool success,) = entryPointSim.simulateExecuteUserOpWithErrorString(
            address(safe), address(target), 0, execData, 0
        );
        assertTrue(success);
        assertEq(target.value(), 99);
    }

    /// @notice executeUserOpWithErrorString bubbles up revert data.
    function test_executeUserOpWithErrorString_bubblesRevertData() public {
        (MockSafe safe,,) = _deploySafe(1);
        RevertingTarget target = new RevertingTarget();

        bytes memory execData = abi.encodeWithSelector(RevertingTarget.alwaysReverts.selector);
        (bool success, bytes memory retData) = entryPointSim.simulateExecuteUserOpWithErrorString(
            address(safe), address(target), 0, execData, 0
        );
        assertFalse(success);
        // The revert data should be Error(string) from "intentional revert"
        // Decode: skip 4-byte selector, then ABI-decode the string
        assertGt(retData.length, 4, "Should have revert data");
        bytes4 errorSig = bytes4(retData);
        assertEq(errorSig, bytes4(keccak256("Error(string)")), "Should be Error(string)");
    }

    /// @notice executeUserOpWithErrorString bubbles up custom errors.
    function test_executeUserOpWithErrorString_bubblesCustomError() public {
        (MockSafe safe,,) = _deploySafe(1);
        RevertingTarget target = new RevertingTarget();

        bytes memory execData = abi.encodeWithSelector(RevertingTarget.revertsWithCustomError.selector);
        (bool success, bytes memory retData) = entryPointSim.simulateExecuteUserOpWithErrorString(
            address(safe), address(target), 0, execData, 0
        );
        assertFalse(success);
        bytes4 errorSig = bytes4(retData);
        assertEq(errorSig, RevertingTarget.CustomError.selector, "Should bubble up CustomError");
    }

    /// @notice executeUserOpWithErrorString from non-entry-point reverts.
    function test_executeUserOpWithErrorString_unsupportedEntryPoint() public {
        (MockSafe safe,,) = _deploySafe(1);

        address fakeEP = makeAddr("fakeEP");
        vm.prank(fakeEP);
        (bool success, bytes memory retData) = address(safe).call(
            abi.encodeWithSelector(
                Safe4337MultiChainSignatureModule.executeUserOpWithErrorString.selector,
                address(0), 0, "", 0
            )
        );
        assertFalse(success);
        bytes4 errorSelector = bytes4(retData);
        assertEq(errorSelector, Safe4337MultiChainSignatureModule.UnsupportedEntryPoint.selector);
    }

    // =========================================================================
    // Section 16: Paymaster Data Handling
    // =========================================================================

    /// @notice Empty paymaster data hashes correctly.
    function test_paymasterDataKeccak_empty() public view {
        bytes memory data = "";
        bytes32 result = module.exposed_paymasterDataKeccak(data);
        assertEq(result, keccak256(data));
    }

    /// @notice Paymaster data without magic suffix hashes as plain keccak.
    function test_paymasterDataKeccak_noMagic() public view {
        // 62 bytes of data but no magic suffix
        bytes memory data = new bytes(62);
        data[0] = 0x01;
        bytes32 result = module.exposed_paymasterDataKeccak(data);
        assertEq(result, keccak256(data));
    }

    /// @notice Paymaster data shorter than MIN_PAYMASTER_DATA_WITH_SUFFIX_LEN hashes as plain keccak.
    function test_paymasterDataKeccak_tooShort() public view {
        bytes memory data = hex"aabbccdd";
        bytes32 result = module.exposed_paymasterDataKeccak(data);
        assertEq(result, keccak256(data));
    }

    /// @notice Paymaster data with magic suffix strips the signature from the hash.
    function test_paymasterDataKeccak_withMagic_stripsSignature() public view {
        // Build paymaster data:
        // [52-byte header][paymaster signature (4 bytes)][2-byte pmSigLength (= 4)][8-byte magic]
        // Total = 52 + 4 + 2 + 8 = 66 bytes
        bytes memory paymasterHeader = new bytes(52);
        paymasterHeader[0] = 0xff; // some paymaster address byte
        bytes memory pmSig = hex"deadbeef"; // 4-byte paymaster signature
        uint16 pmSigLength = 4;
        bytes8 magic = bytes8(0x22e325a297439656);

        bytes memory data = abi.encodePacked(paymasterHeader, pmSig, pmSigLength, magic);

        bytes32 result = module.exposed_paymasterDataKeccak(data);

        // Expected: hash of header + magic (stripping signature + length + magic, then appending magic)
        bytes32 expected = keccak256(abi.encodePacked(paymasterHeader, magic));
        assertEq(result, expected);
    }

    /// @notice Paymaster signature length too large should revert.
    function test_getPaymasterSignatureLength_invalidLength_reverts() public {
        // Build data where pmSigLength > dataLength - 62
        // Header = 52 bytes, then magic suffix (2 + 8 = 10 bytes)
        // Total = 62 bytes, pmSigLength = 1 (but there's 0 bytes available for signature)
        bytes memory header = new bytes(52);
        uint16 pmSigLength = 1; // Claims 1 byte of signature, but there are 0 bytes available
        bytes8 magic = bytes8(0x22e325a297439656);
        bytes memory data = abi.encodePacked(header, pmSigLength, magic);

        vm.expectRevert(abi.encodeWithSelector(
            UserOperationLib.InvalidPaymasterSignatureLength.selector,
            data.length,
            uint256(1)
        ));
        module.exposed_getPaymasterSignatureLength(data);
    }

    /// @notice getPaymasterSignatureLength returns 0 for data without magic.
    function test_getPaymasterSignatureLength_noMagic_returns0() public view {
        bytes memory data = new bytes(70);
        uint256 result = module.exposed_getPaymasterSignatureLength(data);
        assertEq(result, 0);
    }

    /// @notice getPaymasterSignatureLength returns correct length with valid magic.
    function test_getPaymasterSignatureLength_validMagic() public view {
        bytes memory header = new bytes(52);
        bytes memory pmSig = new bytes(10); // 10-byte paymaster signature
        uint16 pmSigLength = 10;
        bytes8 magic = bytes8(0x22e325a297439656);
        bytes memory data = abi.encodePacked(header, pmSig, pmSigLength, magic);

        uint256 result = module.exposed_getPaymasterSignatureLength(data);
        assertEq(result, 10);
    }

    /// @notice Two userOps with same paymaster data but different paymaster signatures produce the same operation hash.
    function test_paymasterSignature_doesNotAffectLeaf() public {
        (MockSafe safe,,) = _deploySafe(1);

        bytes memory header = new bytes(52);
        header[0] = 0xaa;
        bytes8 magic = bytes8(0x22e325a297439656);

        // UserOp 1: 4-byte paymaster signature
        bytes memory pmData1 = abi.encodePacked(header, hex"11111111", uint16(4), magic);
        // UserOp 2: different 4-byte paymaster signature
        bytes memory pmData2 = abi.encodePacked(header, hex"22222222", uint16(4), magic);

        bytes memory dummySig = abi.encodePacked(uint8(0), uint48(0), uint48(0));

        PackedUserOperation memory userOp1 = PackedUserOperation({
            sender: address(safe),
            nonce: 0,
            initCode: "",
            callData: abi.encodeWithSelector(module.executeUserOp.selector, address(0), 0, "", 0),
            accountGasLimits: bytes32(uint256(100000) << 128 | uint256(100000)),
            preVerificationGas: 21000,
            gasFees: bytes32(uint256(1 gwei) << 128 | uint256(1 gwei)),
            paymasterAndData: pmData1,
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
            paymasterAndData: pmData2,
            signature: dummySig
        });

        bytes32 hash1 = proxy.getOperationHash(userOp1);
        bytes32 hash2 = proxy.getOperationHash(userOp2);
        assertEq(hash1, hash2, "Different paymaster signatures should produce same hash");
    }

    /// @notice Different paymaster non-signature data produces different operation hashes.
    function test_paymasterData_nonSigPart_affectsLeaf() public {
        (MockSafe safe,,) = _deploySafe(1);

        // Two different paymaster headers (non-signature data)
        bytes memory header1 = new bytes(52);
        header1[0] = 0xaa;
        bytes memory header2 = new bytes(52);
        header2[0] = 0xbb;

        bytes8 magic = bytes8(0x22e325a297439656);
        bytes memory pmData1 = abi.encodePacked(header1, hex"aabbccdd", uint16(4), magic);
        bytes memory pmData2 = abi.encodePacked(header2, hex"aabbccdd", uint16(4), magic);

        bytes memory dummySig = abi.encodePacked(uint8(0), uint48(0), uint48(0));

        PackedUserOperation memory userOp1 = PackedUserOperation({
            sender: address(safe),
            nonce: 0,
            initCode: "",
            callData: abi.encodeWithSelector(module.executeUserOp.selector, address(0), 0, "", 0),
            accountGasLimits: bytes32(uint256(100000) << 128 | uint256(100000)),
            preVerificationGas: 21000,
            gasFees: bytes32(uint256(1 gwei) << 128 | uint256(1 gwei)),
            paymasterAndData: pmData1,
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
            paymasterAndData: pmData2,
            signature: dummySig
        });

        bytes32 hash1 = proxy.getOperationHash(userOp1);
        bytes32 hash2 = proxy.getOperationHash(userOp2);
        assertTrue(hash1 != hash2, "Different paymaster data should produce different hashes");
    }

    /// @notice calldataKeccak matches keccak256 for arbitrary data.
    function test_calldataKeccak_matchesKeccak() public view {
        bytes memory data = hex"deadbeefcafebabe0123456789abcdef";
        bytes32 result = module.exposed_calldataKeccak(data);
        assertEq(result, keccak256(data));
    }

    /// @notice calldataKeccakWithSuffix matches abi.encodePacked + keccak.
    function test_calldataKeccakWithSuffix_matchesExpected() public view {
        bytes memory data = hex"aabbccdd11223344";
        uint256 len = 4; // use first 4 bytes
        bytes8 suffix = bytes8(0x1122334455667788);

        bytes32 result = module.exposed_calldataKeccakWithSuffix(data, len, suffix);
        // Expected: keccak256(data[0:4] ++ suffix)
        bytes32 expected = keccak256(abi.encodePacked(hex"aabbccdd", suffix));
        assertEq(result, expected);
    }

    /// @notice Zero-length paymaster signature with magic returns 0.
    function test_paymasterSignature_zeroLength() public view {
        bytes memory header = new bytes(52);
        uint16 pmSigLength = 0;
        bytes8 magic = bytes8(0x22e325a297439656);
        bytes memory data = abi.encodePacked(header, pmSigLength, magic);

        uint256 result = module.exposed_getPaymasterSignatureLength(data);
        assertEq(result, 0);
    }

    // =========================================================================
    // Section 17: Deep Merkle Trees (depth 4-10)
    // =========================================================================

    /// @notice Depth 4 merkle tree with 16 leaves.
    function test_multiChain_depth4_validProof() public {
        (MockSafe safe,, uint256[] memory pks) = _deploySafe(1);

        PackedUserOperation memory userOp = _buildModuleUserOp(address(safe), 0);
        (bytes memory opData,,,,,) = proxy.getSafeOp(userOp);
        bytes32 leaf0 = keccak256(opData);

        (bytes32 root, bytes memory proof) = _buildBalancedTree(leaf0, 4);

        bytes32 merkleRootHash = _merkleRootEIP712Hash(root);
        bytes memory signatures = _signSafe(merkleRootHash, pks, 1);

        userOp.signature = abi.encodePacked(uint8(4), uint48(0), uint48(0), proof, signatures);

        uint256 validationData = proxy.validateSignatures(userOp);
        assertEq(validationData, 0);
    }

    /// @notice Depth 5 merkle tree.
    function test_multiChain_depth5_validProof() public {
        (MockSafe safe,, uint256[] memory pks) = _deploySafe(1);

        PackedUserOperation memory userOp = _buildModuleUserOp(address(safe), 0);
        (bytes memory opData,,,,,) = proxy.getSafeOp(userOp);
        bytes32 leaf0 = keccak256(opData);

        (bytes32 root, bytes memory proof) = _buildBalancedTree(leaf0, 5);

        bytes32 merkleRootHash = _merkleRootEIP712Hash(root);
        bytes memory signatures = _signSafe(merkleRootHash, pks, 1);

        userOp.signature = abi.encodePacked(uint8(5), uint48(0), uint48(0), proof, signatures);

        uint256 validationData = proxy.validateSignatures(userOp);
        assertEq(validationData, 0);
    }

    /// @notice Depth 10 (MAX_MERKLE_DEPTH) full validation.
    function test_multiChain_depth10_fullValidation() public {
        (MockSafe safe,, uint256[] memory pks) = _deploySafe(1);

        PackedUserOperation memory userOp = _buildModuleUserOp(address(safe), 0);
        (bytes memory opData,,,,,) = proxy.getSafeOp(userOp);
        bytes32 leaf0 = keccak256(opData);

        (bytes32 root, bytes memory proof) = _buildBalancedTree(leaf0, 10);

        bytes32 merkleRootHash = _merkleRootEIP712Hash(root);
        bytes memory signatures = _signSafe(merkleRootHash, pks, 1);

        userOp.signature = abi.encodePacked(uint8(10), uint48(0), uint48(0), proof, signatures);

        uint256 validationData = proxy.validateSignatures(userOp);
        assertEq(validationData, 0);
    }

    /// @notice Declaring wrong depth (too high) with correct tree should fail.
    function test_multiChain_wrongDepth_tooHigh_fails() public {
        (MockSafe safe,, uint256[] memory pks) = _deploySafe(1);

        PackedUserOperation memory userOp = _buildModuleUserOp(address(safe), 0);
        (bytes memory opData,,,,,) = proxy.getSafeOp(userOp);
        bytes32 leaf = keccak256(opData);

        bytes32 otherLeaf = keccak256("other");
        bytes32 root = _hashPair(leaf, otherLeaf);

        // Correct tree is depth 1, but we declare depth 2 with a fabricated extra sibling
        bytes32 fakeSibling = keccak256("fake");
        bytes memory proof = abi.encodePacked(root, otherLeaf, fakeSibling);

        bytes32 merkleRootHash = _merkleRootEIP712Hash(root);
        bytes memory signatures = _signSafe(merkleRootHash, pks, 1);

        userOp.signature = abi.encodePacked(uint8(2), uint48(0), uint48(0), proof, signatures);

        uint256 validationData = proxy.validateSignatures(userOp);
        _assertSignatureFailed(validationData);
    }

    /// @notice Multi-chain depth 2 with 2-of-3 multi-sig.
    function test_multiChain_depth2_multiSig_2of3() public {
        (MockSafe safe,, uint256[] memory pks) = _deploySafe(2);

        PackedUserOperation memory userOp = _buildModuleUserOp(address(safe), 0);
        (bytes memory opData,,,,,) = proxy.getSafeOp(userOp);
        bytes32 leaf0 = keccak256(opData);

        bytes32 leaf1 = keccak256("chain2");
        bytes32 leaf2 = keccak256("chain3");
        bytes32 leaf3 = keccak256("chain4");

        bytes32 node01 = _hashPair(leaf0, leaf1);
        bytes32 node23 = _hashPair(leaf2, leaf3);
        bytes32 root = _hashPair(node01, node23);

        bytes memory proof = abi.encodePacked(root, node23, leaf1);

        bytes32 merkleRootHash = _merkleRootEIP712Hash(root);
        bytes memory signatures = _signSafe(merkleRootHash, pks, 2);

        userOp.signature = abi.encodePacked(uint8(2), uint48(0), uint48(0), proof, signatures);

        uint256 validationData = proxy.validateSignatures(userOp);
        assertEq(validationData, 0);
    }

    // =========================================================================
    // Section 18: Single-Chain Additional Tests
    // =========================================================================

    /// @notice Single-chain with 2-of-3 multi-sig.
    function test_singleChain_multiSig_2of3() public {
        (MockSafe safe,, uint256[] memory pks) = _deploySafe(2);

        PackedUserOperation memory userOp = _buildModuleUserOp(address(safe), 0);
        (bytes memory opData,,,,,) = proxy.getSafeOp(userOp);
        bytes32 opHash = keccak256(opData);

        bytes memory signatures = _signSafe(opHash, pks, 2);
        userOp.signature = abi.encodePacked(uint8(0), uint48(0), uint48(0), signatures);

        uint256 validationData = proxy.validateSignatures(userOp);
        assertEq(validationData, 0);
    }

    /// @notice Single-chain with 3-of-3 multi-sig.
    function test_singleChain_multiSig_3of3() public {
        (MockSafe safe,, uint256[] memory pks) = _deploySafe(3);

        PackedUserOperation memory userOp = _buildModuleUserOp(address(safe), 0);
        (bytes memory opData,,,,,) = proxy.getSafeOp(userOp);
        bytes32 opHash = keccak256(opData);

        bytes memory signatures = _signSafe(opHash, pks, 3);
        userOp.signature = abi.encodePacked(uint8(0), uint48(0), uint48(0), signatures);

        uint256 validationData = proxy.validateSignatures(userOp);
        assertEq(validationData, 0);
    }

    /// @notice Single-chain empty signatures fails.
    function test_singleChain_emptySignatures_fails() public {
        (MockSafe safe,,) = _deploySafe(1);

        PackedUserOperation memory userOp = _buildModuleUserOp(address(safe), 0);
        // No signatures after the header
        userOp.signature = abi.encodePacked(uint8(0), uint48(0), uint48(0));

        uint256 validationData = proxy.validateSignatures(userOp);
        _assertSignatureFailed(validationData);
    }

    /// @notice Different sender address changes the leaf hash.
    function test_sender_affectsLeaf() public {
        (MockSafe safe1,,) = _deploySafe(1);
        (MockSafe safe2,,) = _deploySafe(1);

        PackedUserOperation memory userOp1 = _buildModuleUserOp(address(safe1), 0);
        PackedUserOperation memory userOp2 = _buildModuleUserOp(address(safe2), 0);

        bytes32 hash1 = proxy.getOperationHash(userOp1);
        bytes32 hash2 = proxy.getOperationHash(userOp2);
        assertTrue(hash1 != hash2, "Different sender must produce different hashes");
    }

    /// @notice validAfter and validUntil timestamps affect the leaf hash.
    function test_timestamps_affectLeaf() public {
        (MockSafe safe,,) = _deploySafe(1);

        PackedUserOperation memory userOp1 = _buildModuleUserOpWithTimestamps(address(safe), 0, 100, 200);
        PackedUserOperation memory userOp2 = _buildModuleUserOpWithTimestamps(address(safe), 0, 300, 400);

        bytes32 hash1 = proxy.getOperationHash(userOp1);
        bytes32 hash2 = proxy.getOperationHash(userOp2);
        assertTrue(hash1 != hash2, "Different timestamps must produce different hashes");
    }

    // =========================================================================
    // Section 19: Fuzz Tests
    // =========================================================================

    /// @notice Fuzz: depth 0-10 should not revert on _getSafeOp (given enough proof data).
    function testFuzz_getSafeOp_validDepths(uint8 rawDepth) public view {
        uint8 depth = rawDepth % 11; // 0..10
        uint256 proofLen = depth == 0 ? 0 : (uint256(depth) + 1) * 32;
        bytes memory proof = new bytes(proofLen);
        bytes memory fakeSig = hex"aa";

        bytes memory signature = abi.encodePacked(depth, uint48(0), uint48(0), proof, fakeSig);
        PackedUserOperation memory userOp = _buildUserOp(address(module), signature);

        // Should not revert
        proxy.getSafeOp(userOp);
    }

    /// @notice Fuzz: depth 11-255 should always revert.
    function testFuzz_getSafeOp_invalidDepths(uint8 rawDepth) public {
        vm.assume(rawDepth > 10);
        bytes memory signature = abi.encodePacked(rawDepth, uint48(0), uint48(0));
        PackedUserOperation memory userOp = _buildUserOp(address(module), signature);

        vm.expectRevert(abi.encodeWithSelector(
            Safe4337MultiChainSignatureModule.MerkleDepthTooLarge.selector, uint256(rawDepth)
        ));
        proxy.getSafeOp(userOp);
    }

    /// @notice Fuzz: random timestamps are correctly round-tripped through _getSafeOp.
    function testFuzz_timestamps_roundtrip(uint48 validAfter, uint48 validUntil) public view {
        bytes memory signature = abi.encodePacked(uint8(0), validAfter, validUntil, new bytes(65));
        PackedUserOperation memory userOp = _buildUserOp(address(module), signature);

        (,, uint8 retDepth, uint48 retValidAfter, uint48 retValidUntil,) = proxy.getSafeOp(userOp);
        assertEq(retDepth, 0);
        assertEq(retValidAfter, validAfter);
        assertEq(retValidUntil, validUntil);
    }

    /// @notice Fuzz: _checkSignaturesLength accepts exact EOA lengths.
    function testFuzz_checkSignaturesLength_exactEOA(uint8 rawThreshold) public view {
        uint256 threshold = (uint256(rawThreshold) % 10) + 1; // 1..10
        bytes memory sig = new bytes(threshold * 65);
        // Set all signature types to non-zero (EOA: v = 27 or 28)
        for (uint256 i = 0; i < threshold; i++) {
            sig[i * 65 + 64] = bytes1(uint8(27));
        }
        assertTrue(proxy.checkSignaturesLength(sig, threshold));
    }

    /// @notice Fuzz: _checkSignaturesLength rejects length = threshold * 65 - 1.
    function testFuzz_checkSignaturesLength_oneByteTooShort(uint8 rawThreshold) public view {
        uint256 threshold = (uint256(rawThreshold) % 10) + 1;
        uint256 tooShortLen = threshold * 65 - 1;
        bytes memory sig = new bytes(tooShortLen);
        assertFalse(proxy.checkSignaturesLength(sig, threshold));
    }

    /// @notice Fuzz: single-chain validation with random nonce.
    function testFuzz_singleChain_randomNonce(uint256 nonce) public {
        (MockSafe safe,, uint256[] memory pks) = _deploySafe(1);

        PackedUserOperation memory userOp = _buildModuleUserOp(address(safe), nonce);
        (bytes memory opData,,,,,) = proxy.getSafeOp(userOp);
        bytes32 opHash = keccak256(opData);

        bytes memory signatures = _signSafe(opHash, pks, 1);
        userOp.signature = abi.encodePacked(uint8(0), uint48(0), uint48(0), signatures);

        uint256 validationData = proxy.validateSignatures(userOp);
        assertEq(validationData, 0);
    }

    /// @notice Fuzz: calldataKeccak matches keccak256 for random data.
    function testFuzz_calldataKeccak(bytes memory data) public view {
        bytes32 result = module.exposed_calldataKeccak(data);
        assertEq(result, keccak256(data));
    }

    // =========================================================================
    // Section 20: _checkSignaturesLength Edge Cases
    // =========================================================================

    /// @notice Threshold 0 with empty signatures passes (0 * 65 = 0 maxLength).
    function test_checkSignaturesLength_threshold0_empty() public view {
        bytes memory sig = "";
        assertTrue(proxy.checkSignaturesLength(sig, 0));
    }

    /// @notice Multiple contract signatures with dynamic parts.
    function test_checkSignaturesLength_multipleContractSigs() public view {
        // 2 contract signatures:
        // Sig 0: type=0, offset=130 (after both static parts), dynamic length=16
        // Sig 1: type=0, offset=178 (130+32+16), dynamic length=8
        // Total: 130 (2*65 static) + 32+16 + 32+8 = 218
        bytes memory sig = new bytes(218);

        // Sig 0: type 0 at position 64
        sig[64] = 0x00;
        // Sig 0: offset at position 32..63 → 130
        sig[63] = bytes1(uint8(130));

        // Sig 0: dynamic length at byte 130..161 → 16
        sig[161] = bytes1(uint8(16));

        // Sig 1: type 0 at position 129 (65+64)
        sig[129] = 0x00;
        // Sig 1: offset at position 97..128 → 178 (130+32+16)
        sig[128] = bytes1(uint8(178));

        // Sig 1: dynamic length at byte 178..209 → 8
        sig[209] = bytes1(uint8(8));

        assertTrue(proxy.checkSignaturesLength(sig, 2));
    }

    /// @notice Mixed EOA and contract signatures.
    function test_checkSignaturesLength_mixedEOAAndContract() public view {
        // Sig 0: EOA (type = 27), Sig 1: contract (type = 0, offset → dynamic part)
        // Static: 2 * 65 = 130
        // Sig 1 dynamic: 32 (length prefix) + 20 (data) = 52
        // Total: 130 + 52 = 182
        bytes memory sig = new bytes(182);

        // Sig 0: type = 27 at position 64
        sig[64] = bytes1(uint8(27));

        // Sig 1: type = 0 at position 129 (65+64)
        sig[129] = 0x00;
        // Sig 1: offset at position 97..128 → 130 (points to dynamic data start)
        sig[128] = bytes1(uint8(130));

        // Sig 1: dynamic length at byte 130..161 → 20
        sig[161] = bytes1(uint8(20));

        assertTrue(proxy.checkSignaturesLength(sig, 2));
    }

    // =========================================================================
    // Section 21: Cross-Chain Multi-Chain Advanced Tests
    // =========================================================================

    /// @notice Multi-chain proof built on chain A, validated on chain A, then re-deployed on chain B with same tree fails.
    function test_crossChain_multiChain_sameTreeDifferentChains() public {
        (MockSafe safe,, uint256[] memory pks) = _deploySafe(1);

        // Build tree on chain 1
        vm.chainId(1);
        PackedUserOperation memory userOp = _buildModuleUserOp(address(safe), 0);
        (bytes memory opData1,,,,,) = proxy.getSafeOp(userOp);
        bytes32 leaf1 = keccak256(opData1);

        // Build tree on chain 2
        vm.chainId(2);
        (bytes memory opData2,,,,,) = proxy.getSafeOp(userOp);
        bytes32 leaf2 = keccak256(opData2);

        // Both leaves should be in the tree for a proper multi-chain setup
        bytes32 root = _hashPair(leaf1, leaf2);

        // Sign the merkle root (chain-agnostic)
        bytes32 merkleRootHash = _merkleRootEIP712Hash(root);
        bytes memory signatures = _signSafe(merkleRootHash, pks, 1);

        // Validate leaf2 on chain 2 — should pass
        vm.chainId(2);
        bytes memory proof2 = abi.encodePacked(root, leaf1);
        userOp.signature = abi.encodePacked(uint8(1), uint48(0), uint48(0), proof2, signatures);
        uint256 vd2 = proxy.validateSignatures(userOp);
        assertEq(vd2, 0, "Should validate on correct chain");

        // Validate leaf2's proof on chain 1 — should fail (leaf computed from chain 1 differs)
        vm.chainId(1);
        uint256 vd1 = proxy.validateSignatures(userOp);
        _assertSignatureFailed(vd1);
    }

    /// @notice Multi-chain: proper dual-chain tree where both leaves validate on their respective chains.
    function test_crossChain_dualChainTree_bothChainsValid() public {
        (MockSafe safe,, uint256[] memory pks) = _deploySafe(1);

        PackedUserOperation memory userOp = _buildModuleUserOp(address(safe), 0);

        // Get leaf for chain 1
        vm.chainId(1);
        (bytes memory opData1,,,,,) = proxy.getSafeOp(userOp);
        bytes32 leafChain1 = keccak256(opData1);

        // Get leaf for chain 2
        vm.chainId(2);
        (bytes memory opData2,,,,,) = proxy.getSafeOp(userOp);
        bytes32 leafChain2 = keccak256(opData2);

        bytes32 root = _hashPair(leafChain1, leafChain2);
        bytes32 merkleRootHash = _merkleRootEIP712Hash(root);
        bytes memory signatures = _signSafe(merkleRootHash, pks, 1);

        // Validate on chain 1
        vm.chainId(1);
        bytes memory proof1 = abi.encodePacked(root, leafChain2);
        userOp.signature = abi.encodePacked(uint8(1), uint48(0), uint48(0), proof1, signatures);
        uint256 vd1 = proxy.validateSignatures(userOp);
        assertEq(vd1, 0, "Should validate on chain 1");

        // Validate on chain 2
        vm.chainId(2);
        bytes memory proof2 = abi.encodePacked(root, leafChain1);
        userOp.signature = abi.encodePacked(uint8(1), uint48(0), uint48(0), proof2, signatures);
        uint256 vd2 = proxy.validateSignatures(userOp);
        assertEq(vd2, 0, "Should validate on chain 2");
    }

    // =========================================================================
    // Section 22: Paymaster with validateUserOp Integration
    // =========================================================================

    /// @notice Paymaster signature excluded from hash in full validateUserOp flow.
    function test_validateUserOp_paymasterSig_excluded() public {
        (MockSafe safe,, uint256[] memory pks) = _deploySafe(1);

        bytes memory header = new bytes(52);
        header[0] = 0xcc;
        bytes8 magic = bytes8(0x22e325a297439656);
        bytes memory pmData = abi.encodePacked(header, hex"deadbeef", uint16(4), magic);

        bytes memory dummySig = abi.encodePacked(uint8(0), uint48(0), uint48(0));
        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(safe),
            nonce: 0,
            initCode: "",
            callData: abi.encodeWithSelector(module.executeUserOp.selector, address(0), 0, "", 0),
            accountGasLimits: bytes32(uint256(100000) << 128 | uint256(100000)),
            preVerificationGas: 21000,
            gasFees: bytes32(uint256(1 gwei) << 128 | uint256(1 gwei)),
            paymasterAndData: pmData,
            signature: dummySig
        });

        (bytes memory opData,,,,,) = proxy.getSafeOp(userOp);
        bytes32 opHash = keccak256(opData);
        bytes memory signatures = _signSafe(opHash, pks, 1);
        userOp.signature = abi.encodePacked(uint8(0), uint48(0), uint48(0), signatures);

        uint256 validationData = entryPointSim.simulateValidateUserOp(
            address(safe), userOp, bytes32(0), 0
        );
        assertEq(validationData, 0, "Should validate with paymaster data");
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
        address authorizer = address(uint160(validationData));
        assertEq(authorizer, address(1), "Expected signature validation failure");
    }

    /**
     * @dev Builds a balanced merkle tree of the given depth with leaf0 at position 0.
     *      Returns the root and proof for leaf0.
     *      Proof format: [root, sibling_at_depth_1, sibling_at_depth_2, ..., sibling_at_depth_N]
     */
    function _buildBalancedTree(bytes32 leaf0, uint256 depth) internal pure returns (bytes32 root, bytes memory proof) {
        require(depth > 0 && depth <= 10, "Invalid depth");

        // Build bottom-up. At each level, leaf0's hash is paired with a generated sibling.
        bytes32[] memory siblings = new bytes32[](depth);
        bytes32 currentHash = leaf0;

        for (uint256 i = 0; i < depth; i++) {
            // Generate a deterministic sibling
            bytes32 sibling = keccak256(abi.encodePacked("sibling", i));

            // For higher levels, make sibling a proper subtree hash
            for (uint256 j = 0; j < i; j++) {
                bytes32 subSibling = keccak256(abi.encodePacked("subtree", i, j));
                sibling = _hashPair(sibling, subSibling);
            }

            siblings[depth - 1 - i] = sibling; // Store in reverse (proof is top-down in contract)
            currentHash = _hashPair(currentHash, sibling);
        }
        root = currentHash;

        // Proof: [root, siblings from top to bottom]
        proof = abi.encodePacked(root);
        for (uint256 i = 0; i < depth; i++) {
            proof = abi.encodePacked(proof, siblings[i]);
        }
    }
}
