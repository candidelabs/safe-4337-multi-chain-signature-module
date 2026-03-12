// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {EntryPoint} from "@account-abstraction/contracts/core/EntryPoint.sol";
import {Safe4337MultiChainSignatureModule} from "../Safe4337MultiChainSignatureModule.sol";
import {SafeProxyFactory} from "@safe-global/safe-contracts/contracts/proxies/SafeProxyFactory.sol";
import {SafeL2} from "@safe-global/safe-contracts/contracts/SafeL2.sol";
import {SafeModuleSetup} from "./helpers/SafeModuleSetup.sol";
import {TestSafeSignerLaunchpad} from "./helpers/TestSafeSignerLaunchpad.sol";
import {TestUniqueSignerFactory, TestUniqueSigner} from "./helpers/TestUniqueSigner.sol";

/**
 * @title Unique Signers Tests
 * @notice Mirrors test scenarios from safe-modules reference tests:
 *   - UniqueSigner.spec.ts: Unique signer deployment via launchpad
 * @dev Tests deploying a Safe via a launchpad contract that creates unique signers
 *      during the first user operation using ERC-4337.
 */
contract UniqueSignersTest is Test {
    EntryPoint internal entryPoint;
    Safe4337MultiChainSignatureModule internal module;
    SafeProxyFactory internal proxyFactory;
    SafeL2 internal safeSingleton;
    SafeModuleSetup internal safeModuleSetup;
    TestSafeSignerLaunchpad internal signerLaunchpad;
    TestUniqueSignerFactory internal signerFactory;

    address internal relayer;
    uint256 internal constant USER_PK = 0xA11CE;

    function setUp() public {
        entryPoint = new EntryPoint();
        module = new Safe4337MultiChainSignatureModule(address(entryPoint));
        proxyFactory = new SafeProxyFactory();
        safeSingleton = new SafeL2();
        safeModuleSetup = new SafeModuleSetup();

        signerLaunchpad = new TestSafeSignerLaunchpad(address(entryPoint));
        signerFactory = new TestUniqueSignerFactory();

        relayer = makeAddr("relayer");
    }

    // =========================================================================
    // Deploy Safe with unique signer via launchpad
    // Ref: UniqueSigner.spec.ts "should execute a user op and deploy a unique signer"
    // =========================================================================

    function test_uniqueSigner_deployAndExecute() public {
        uint256 key = uint256(keccak256(abi.encodePacked(uint256(1))));
        bytes memory signerData = abi.encode(key);
        address signerAddr = signerFactory.getSigner(signerData);

        bytes memory enableModulesData = _buildEnableModulesData();
        bytes32 initHash = signerLaunchpad.getInitHash(
            address(safeSingleton), address(signerFactory), signerData,
            address(safeModuleSetup), enableModulesData, address(module)
        );

        bytes memory launchpadInitializer = abi.encodeWithSelector(
            TestSafeSignerLaunchpad.preValidationSetup.selector, initHash, address(0), ""
        );

        // Compute Safe address via CREATE2 without deploying
        uint256 freshSalt = 99999;
        address freshSafeAddress = _computeLaunchpadAddress(launchpadInitializer, freshSalt);

        vm.deal(freshSafeAddress, 1 ether);
        assertEq(freshSafeAddress.code.length, 0, "Safe should not be deployed yet");

        // Build and sign user operation
        PackedUserOperation memory userOp;
        {
            bytes memory initCode = _buildLaunchpadInitCode(launchpadInitializer, freshSalt);
            bytes memory callData = _buildInitializeThenUserOpCallData(signerData, enableModulesData);

            userOp = PackedUserOperation({
                sender: freshSafeAddress,
                nonce: 0,
                initCode: initCode,
                callData: callData,
                accountGasLimits: _packGasLimits(700000, 2000000),
                preVerificationGas: 100000,
                gasFees: _packGasFees(1 gwei, 1 gwei),
                paymasterAndData: "",
                signature: ""
            });
        }

        {
            bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
            bytes32 safeInitOpHash = signerLaunchpad.getOperationHash(userOpHash, 0, 0);
            uint256 xorSig = uint256(safeInitOpHash) ^ key;
            userOp.signature = abi.encodePacked(uint48(0), uint48(0), bytes32(xorSig));
        }

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        vm.prank(relayer, relayer);
        entryPoint.handleOps(ops, payable(relayer));

        // Verify deployment and configuration
        assertGt(freshSafeAddress.code.length, 0, "Safe should be deployed");
        bytes32 implSlot = vm.load(freshSafeAddress, bytes32(0));
        assertEq(address(uint160(uint256(implSlot))), address(safeSingleton), "Implementation should be SafeL2");

        SafeL2 safe = SafeL2(payable(freshSafeAddress));
        address[] memory owners = safe.getOwners();
        assertEq(owners.length, 1, "Should have 1 owner");
        assertEq(owners[0], signerAddr, "Owner should be the unique signer");
    }

    function _buildEnableModulesData() internal view returns (bytes memory) {
        address[] memory modules = new address[](1);
        modules[0] = address(module);
        return abi.encodeWithSignature("enableModules(address[])", modules);
    }

    function _computeLaunchpadAddress(bytes memory launchpadInitializer, uint256 salt) internal view returns (address) {
        bytes memory proxyCreationCode = proxyFactory.proxyCreationCode();
        bytes memory deploymentData = abi.encodePacked(proxyCreationCode, uint256(uint160(address(signerLaunchpad))));
        bytes32 create2Salt = keccak256(abi.encodePacked(keccak256(launchpadInitializer), salt));
        return address(uint160(uint256(keccak256(abi.encodePacked(
            bytes1(0xff), address(proxyFactory), create2Salt, keccak256(deploymentData)
        )))));
    }

    function _buildLaunchpadInitCode(bytes memory launchpadInitializer, uint256 salt) internal view returns (bytes memory) {
        return abi.encodePacked(
            address(proxyFactory),
            abi.encodeWithSignature(
                "createProxyWithNonce(address,bytes,uint256)",
                address(signerLaunchpad), launchpadInitializer, salt
            )
        );
    }

    function _buildInitializeThenUserOpCallData(bytes memory signerData, bytes memory enableModulesData) internal view returns (bytes memory) {
        bytes memory innerCallData = abi.encodeWithSelector(
            module.executeUserOp.selector, relayer, 0.5 ether, "", uint8(0)
        );
        return abi.encodeWithSelector(
            TestSafeSignerLaunchpad.initializeThenUserOp.selector,
            address(safeSingleton), address(signerFactory), signerData,
            address(safeModuleSetup), enableModulesData, address(module), innerCallData
        );
    }

    // =========================================================================
    // Unique signer factory address prediction
    // =========================================================================

    function test_uniqueSigner_factoryAddressPrediction() public {
        uint256 key1 = uint256(keccak256("key1"));
        uint256 key2 = uint256(keccak256("key2"));

        address predicted1 = signerFactory.getSigner(abi.encode(key1));
        address predicted2 = signerFactory.getSigner(abi.encode(key2));

        assertTrue(predicted1 != predicted2, "Different keys should give different signer addresses");

        // Deploy signer1 and verify address
        signerFactory.createSigner(abi.encode(key1));
        assertGt(predicted1.code.length, 0, "Signer should be deployed at predicted address");

        // Calling create again should not revert (already deployed)
        signerFactory.createSigner(abi.encode(key1));
    }

    // =========================================================================
    // Unique signer signature validation
    // =========================================================================

    function test_uniqueSigner_signatureValidation() public {
        uint256 key = uint256(keccak256("testkey"));
        signerFactory.createSigner(abi.encode(key));
        address signerAddr = signerFactory.getSigner(abi.encode(key));

        TestUniqueSigner signer = TestUniqueSigner(signerAddr);

        // Valid signature: message = signature ^ key
        bytes memory data = "test data";
        uint256 message = uint256(keccak256(data));
        uint256 sig = message ^ key;

        bytes4 result = signer.isValidSignature(data, abi.encode(sig));
        assertEq(result, signer.isValidSignature.selector, "Valid signature should work");

        // Invalid signature
        bytes4 badResult = signer.isValidSignature(data, abi.encode(sig + 1));
        assertEq(badResult, bytes4(0), "Invalid signature should fail");
    }

    // =========================================================================
    // Unique signer factory isValidSignatureForSigner
    // =========================================================================

    function test_uniqueSigner_factorySignatureValidation() public {
        uint256 key = uint256(keccak256("factorykey"));
        bytes memory signerData = abi.encode(key);

        bytes32 message = keccak256("test message for factory");
        uint256 sig = uint256(message) ^ key;

        bytes4 result = signerFactory.isValidSignatureForSigner(
            message,
            abi.encode(sig),
            signerData
        );
        assertEq(result, signerFactory.isValidSignatureForSigner.selector, "Valid factory signature should work");

        // Invalid
        bytes4 badResult = signerFactory.isValidSignatureForSigner(
            message,
            abi.encode(sig + 1),
            signerData
        );
        assertEq(badResult, bytes4(0), "Invalid factory signature should fail");
    }

    // =========================================================================
    // Launchpad init hash computation
    // =========================================================================

    function test_uniqueSigner_launchpadInitHash() public view {
        uint256 key = uint256(keccak256(abi.encodePacked(uint256(1))));
        bytes memory signerData = abi.encode(key);

        address[] memory modules = new address[](1);
        modules[0] = address(module);
        bytes memory setupData = abi.encodeWithSignature("enableModules(address[])", modules);

        bytes32 initHash = signerLaunchpad.getInitHash(
            address(safeSingleton),
            address(signerFactory),
            signerData,
            address(safeModuleSetup),
            setupData,
            address(module)
        );

        // Verify it's deterministic
        bytes32 initHash2 = signerLaunchpad.getInitHash(
            address(safeSingleton),
            address(signerFactory),
            signerData,
            address(safeModuleSetup),
            setupData,
            address(module)
        );
        assertEq(initHash, initHash2, "Init hash should be deterministic");

        // Different params should give different hash
        bytes32 differentHash = signerLaunchpad.getInitHash(
            address(safeSingleton),
            address(signerFactory),
            abi.encode(key + 1),
            address(safeModuleSetup),
            setupData,
            address(module)
        );
        assertTrue(initHash != differentHash, "Different params should give different hash");
    }

    // =========================================================================
    // Launchpad operation hash
    // =========================================================================

    function test_uniqueSigner_launchpadOperationHash() public view {
        bytes32 userOpHash = keccak256("user op hash");
        uint48 validAfter = 100;
        uint48 validUntil = 200;

        bytes32 opHash1 = signerLaunchpad.getOperationHash(userOpHash, validAfter, validUntil);

        // Deterministic
        bytes32 opHash2 = signerLaunchpad.getOperationHash(userOpHash, validAfter, validUntil);
        assertEq(opHash1, opHash2);

        // Changes with userOpHash
        bytes32 opHash3 = signerLaunchpad.getOperationHash(keccak256("different"), validAfter, validUntil);
        assertTrue(opHash1 != opHash3);

        // Changes with timestamps
        bytes32 opHash4 = signerLaunchpad.getOperationHash(userOpHash, validAfter + 1, validUntil);
        assertTrue(opHash1 != opHash4);
    }

    // =========================================================================
    // Internal Helpers
    // =========================================================================

    function _packGasLimits(uint128 verificationGasLimit, uint128 callGasLimit) internal pure returns (bytes32) {
        return bytes32(uint256(verificationGasLimit) << 128 | uint256(callGasLimit));
    }

    function _packGasFees(uint128 maxPriorityFeePerGas, uint128 maxFeePerGas) internal pure returns (bytes32) {
        return bytes32(uint256(maxPriorityFeePerGas) << 128 | uint256(maxFeePerGas));
    }

    receive() external payable {}
}
