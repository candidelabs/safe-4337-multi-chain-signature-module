// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {SafeProxyFactory} from "@safe-global/safe-contracts/contracts/proxies/SafeProxyFactory.sol";
import {SafeL2} from "@safe-global/safe-contracts/contracts/SafeL2.sol";
import {Safe4337MultiChainSignatureModule} from "../Safe4337MultiChainSignatureModule.sol";
import {SafeModuleSetup} from "./helpers/SafeModuleSetup.sol";
import {InitCode} from "./helpers/InitCode.sol";
import {EntryPoint} from "@account-abstraction/contracts/core/EntryPoint.sol";

/**
 * @title InitCode Tests
 * @notice Mirrors test scenarios from safe-modules reference tests:
 *   - InitCode.spec.ts: Init code computation validation
 * @dev Tests that the InitCode contract correctly computes the init code for deploying
 *      Safe proxies with the 4337 module enabled.
 */
contract InitCodeTest is Test {
    EntryPoint internal entryPoint;
    Safe4337MultiChainSignatureModule internal module;
    SafeProxyFactory internal proxyFactory;
    SafeL2 internal safeSingleton;
    SafeModuleSetup internal safeModuleSetup;
    InitCode internal initCodeContract;

    function setUp() public {
        entryPoint = new EntryPoint();
        module = new Safe4337MultiChainSignatureModule(address(entryPoint));
        proxyFactory = new SafeProxyFactory();
        safeSingleton = new SafeL2();
        safeModuleSetup = new SafeModuleSetup();

        initCodeContract = new InitCode(InitCode.Config({
            safeModuleSetup: address(safeModuleSetup),
            erc4337module: address(module),
            safeSingleton: address(safeSingleton),
            proxyFactory: address(proxyFactory)
        }));
    }

    // =========================================================================
    // Compute valid init code
    // Ref: InitCode.spec.ts "should compute the valid init code"
    // =========================================================================

    function test_initCode_computesValidInitCode() public view {
        address owner = address(0xFF);
        address[] memory owners = new address[](1);
        owners[0] = owner;

        bytes memory computedInitCode = initCodeContract.getInitCode(owners, 1, 0);

        // Manually build expected init code
        bytes memory expectedInitCode = _buildExpectedInitCode(owners, 1, 0);

        assertEq(computedInitCode, expectedInitCode, "InitCode should match manual computation");
    }

    // =========================================================================
    // Init code with multiple owners
    // =========================================================================

    function test_initCode_multipleOwners() public view {
        address[] memory owners = new address[](3);
        owners[0] = address(0xAA);
        owners[1] = address(0xBB);
        owners[2] = address(0xCC);

        bytes memory computedInitCode = initCodeContract.getInitCode(owners, 2, 0);
        bytes memory expectedInitCode = _buildExpectedInitCode(owners, 2, 0);

        assertEq(computedInitCode, expectedInitCode, "Multi-owner init code should match");
    }

    // =========================================================================
    // Init code with different salt
    // =========================================================================

    function test_initCode_differentSaltProducesDifferentCode() public view {
        address[] memory owners = new address[](1);
        owners[0] = address(0xFF);

        bytes memory initCode0 = initCodeContract.getInitCode(owners, 1, 0);
        bytes memory initCode1 = initCodeContract.getInitCode(owners, 1, 1);

        assertTrue(keccak256(initCode0) != keccak256(initCode1), "Different salts should produce different init code");
    }

    // =========================================================================
    // Init code produces deployable proxy
    // =========================================================================

    function test_initCode_producesDeployableProxy() public {
        address owner = makeAddr("owner");
        address[] memory owners = new address[](1);
        owners[0] = owner;

        bytes memory computedInitCode = initCodeContract.getInitCode(owners, 1, 42);

        // Extract factory address and calldata from initCode
        address factory;
        bytes memory callData;
        assembly {
            factory := shr(96, mload(add(computedInitCode, 32)))
        }
        callData = new bytes(computedInitCode.length - 20);
        for (uint256 i = 0; i < callData.length; i++) {
            callData[i] = computedInitCode[i + 20];
        }

        // Execute the initCode
        (bool success, bytes memory result) = factory.call(callData);
        assertTrue(success, "InitCode should deploy successfully");

        address deployedProxy = abi.decode(result, (address));
        assertGt(deployedProxy.code.length, 0, "Proxy should be deployed");

        // Verify the deployed Safe configuration
        SafeL2 safe = SafeL2(payable(deployedProxy));
        assertEq(safe.getThreshold(), 1, "Threshold should be 1");

        address[] memory safeOwners = safe.getOwners();
        assertEq(safeOwners.length, 1, "Should have 1 owner");
        assertEq(safeOwners[0], owner, "Owner should match");
    }

    // =========================================================================
    // Init code configuration parameters
    // =========================================================================

    function test_initCode_configParameters() public view {
        assertEq(initCodeContract.SAFE_MODULE_SETUP_ADDRESS(), address(safeModuleSetup));
        assertEq(initCodeContract.SAFE_4337_MODULE_ADDRESS(), address(module));
        assertEq(initCodeContract.SAFE_SINGLETON_ADDRESS(), address(safeSingleton));
        assertEq(initCodeContract.SAFE_PROXY_FACTORY_ADDRESS(), address(proxyFactory));
    }

    // =========================================================================
    // Init code determinism
    // =========================================================================

    function test_initCode_isDeterministic() public view {
        address[] memory owners = new address[](1);
        owners[0] = address(0xFF);

        bytes memory initCode1 = initCodeContract.getInitCode(owners, 1, 0);
        bytes memory initCode2 = initCodeContract.getInitCode(owners, 1, 0);

        assertEq(keccak256(initCode1), keccak256(initCode2), "Init code should be deterministic");
    }

    // =========================================================================
    // Fuzz: init code with various parameters
    // =========================================================================

    function test_initCode_fuzz(uint256 salt) public view {
        address[] memory owners = new address[](1);
        owners[0] = address(0xEE);

        bytes memory computedInitCode = initCodeContract.getInitCode(owners, 1, salt);
        bytes memory expectedInitCode = _buildExpectedInitCode(owners, 1, salt);

        assertEq(computedInitCode, expectedInitCode);
    }

    // =========================================================================
    // Internal Helpers
    // =========================================================================

    function _buildExpectedInitCode(
        address[] memory owners,
        uint256 threshold,
        uint256 saltNonce
    ) internal view returns (bytes memory) {
        address[] memory modules = new address[](1);
        modules[0] = address(module);

        bytes memory initializer = abi.encodeWithSignature(
            "setup(address[],uint256,address,bytes,address,address,uint256,address)",
            owners,
            threshold,
            address(safeModuleSetup),
            abi.encodeWithSignature("enableModules(address[])", modules),
            address(module),
            address(0),
            0,
            address(0)
        );

        bytes memory initCallData = abi.encodeWithSignature(
            "createProxyWithNonce(address,bytes,uint256)",
            address(safeSingleton),
            initializer,
            saltNonce
        );

        return abi.encodePacked(address(proxyFactory), initCallData);
    }
}
