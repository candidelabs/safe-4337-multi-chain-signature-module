// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {EntryPoint} from "@account-abstraction/contracts/core/EntryPoint.sol";
import {Safe4337MultiChainSignatureModule} from "../Safe4337MultiChainSignatureModule.sol";
import {SafeProxyFactory} from "@safe-global/safe-contracts/contracts/proxies/SafeProxyFactory.sol";
import {SafeProxy} from "@safe-global/safe-contracts/contracts/proxies/SafeProxy.sol";
import {SafeL2} from "@safe-global/safe-contracts/contracts/SafeL2.sol";
import {MultiSend} from "@safe-global/safe-contracts/contracts/libraries/MultiSend.sol";
import {SafeModuleSetup} from "./helpers/SafeModuleSetup.sol";
import {TestStakedFactory} from "./helpers/TestStakedFactory.sol";
import {TestSingletonSigner, TestSingletonSignerFactory} from "./helpers/TestSingletonSigner.sol";

/**
 * @title Singleton Signers Tests
 * @notice Mirrors test scenarios from safe-modules reference tests:
 *   - SingletonSigners.spec.ts: Custom singleton signers with alternate signing schemes
 * @dev Tests deploying a Safe with custom contract-based signers that use a XOR-based
 *      signature verification scheme, using a staked factory for ERC-4337 compliance.
 */
contract SingletonSignersTest is Test {
    EntryPoint internal entryPoint;
    Safe4337MultiChainSignatureModule internal module;
    SafeProxyFactory internal proxyFactory;
    SafeL2 internal safeSingleton;
    SafeModuleSetup internal safeModuleSetup;
    MultiSend internal multiSend;
    TestStakedFactory internal stakedFactory;
    TestSingletonSignerFactory internal signerFactory;
    SingletonOpDataHelper internal opDataHelper;

    address internal relayer;
    uint256 internal constant USER_PK = 0xA11CE;

    // Custom signers
    address[] internal customSignerAddrs;
    uint256[] internal customSignerKeys;
    uint256 internal constant NUM_SIGNERS = 3;

    function setUp() public {
        entryPoint = new EntryPoint();
        module = new Safe4337MultiChainSignatureModule(address(entryPoint));
        proxyFactory = new SafeProxyFactory();
        safeSingleton = new SafeL2();
        safeModuleSetup = new SafeModuleSetup();
        multiSend = new MultiSend();
        opDataHelper = new SingletonOpDataHelper(module);

        relayer = makeAddr("relayer");

        // Deploy staked factory
        stakedFactory = new TestStakedFactory(address(proxyFactory));
        stakedFactory.stakeEntryPoint{value: 1 ether}(entryPoint, type(uint32).max);

        // Deploy singleton signer factory and create 3 signers
        signerFactory = new TestSingletonSignerFactory();
        for (uint256 i = 0; i < NUM_SIGNERS; i++) {
            signerFactory.deploySigner(i);
            address signerAddr = signerFactory.getSigner(i);
            uint256 key = uint256(keccak256(abi.encodePacked(uint8(i))));
            customSignerAddrs.push(signerAddr);
            customSignerKeys.push(key);
        }
    }

    // =========================================================================
    // Deploy Safe with singleton signers and execute ETH transfer
    // Ref: SingletonSigners.spec.ts "should deploy a new Safe with alternate signing scheme"
    // =========================================================================

    function test_singletonSigners_deployAndExecute() public {
        // Build MultiSend data: enable module + set keys on all signers
        bytes memory multiSendData;
        {
            // Enable module
            address[] memory modules = new address[](1);
            modules[0] = address(module);
            bytes memory enableModulesData = abi.encodeWithSignature("enableModules(address[])", modules);

            bytes memory txData = abi.encodePacked(
                uint8(1), // delegatecall
                address(safeModuleSetup),
                uint256(0),
                uint256(enableModulesData.length),
                enableModulesData
            );

            // Set keys on signers
            for (uint256 i = 0; i < NUM_SIGNERS; i++) {
                bytes memory setKeyData = abi.encodeWithSelector(TestSingletonSigner.setKey.selector, customSignerKeys[i]);
                txData = abi.encodePacked(
                    txData,
                    uint8(0), // call
                    customSignerAddrs[i],
                    uint256(0),
                    uint256(setKeyData.length),
                    setKeyData
                );
            }

            multiSendData = abi.encodeWithSelector(MultiSend.multiSend.selector, txData);
        }

        // Build Safe setup data
        bytes memory setupData;
        {
            setupData = abi.encodeWithSignature(
                "setup(address[],uint256,address,bytes,address,address,uint256,address)",
                customSignerAddrs,
                NUM_SIGNERS,
                address(multiSend),
                multiSendData,
                address(module),
                address(0),
                0,
                address(0)
            );
        }

        // Compute Safe address without deploying (CREATE2 prediction)
        address safeAddress = _predictSafeAddress(setupData, 1);
        vm.deal(safeAddress, 2 ether);
        assertEq(safeAddress.code.length, 0, "Safe should not be deployed yet");

        // Build initCode via staked factory
        bytes memory initCode;
        {
            bytes memory createProxyData = abi.encodeWithSignature(
                "createProxyWithNonce(address,bytes,uint256)",
                address(safeSingleton),
                setupData,
                uint256(1)
            );
            initCode = abi.encodePacked(address(stakedFactory), createProxyData);
        }

        // Build user operation
        address receiver = vm.addr(USER_PK);
        PackedUserOperation memory userOp = PackedUserOperation({
            sender: safeAddress,
            nonce: 0,
            initCode: initCode,
            callData: abi.encodeWithSelector(module.executeUserOp.selector, receiver, 0.1 ether, "", uint8(0)),
            accountGasLimits: _packGasLimits(800000, 500000),
            preVerificationGas: 100000,
            gasFees: _packGasFees(1 gwei, 1 gwei),
            paymasterAndData: "",
            signature: abi.encodePacked(uint8(0), uint48(0), uint48(0))
        });

        // Get operation hash and build XOR-based signatures
        bytes32 opHash;
        {
            opHash = module.getOperationHash(userOp);
        }

        // Build Safe contract signatures for all custom signers
        bytes memory signatures = _buildCustomSignatures(opHash);
        userOp.signature = abi.encodePacked(uint8(0), uint48(0), uint48(0), signatures);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        vm.prank(relayer, relayer);
        entryPoint.handleOps(ops, payable(relayer));

        assertGt(safeAddress.code.length, 0, "Safe should be deployed");
        assertLt(address(safeAddress).balance, 1.9 ether, "Safe should have paid fees");
    }

    // =========================================================================
    // Singleton signer key verification
    // =========================================================================

    function test_singletonSigners_keyVerification() public {
        // Deploy a signer and set its key directly (simulating Safe calling setKey)
        TestSingletonSigner signer = TestSingletonSigner(customSignerAddrs[0]);
        uint256 key = customSignerKeys[0];

        // Set the key as if called by a specific address
        address caller = makeAddr("caller");
        vm.prank(caller);
        signer.setKey(key);

        // Verify the key is set
        (, uint256 storedKey) = signer.keys(caller);
        assertEq(storedKey, key, "Key should be set");

        // Verify signature scheme works (isValidSignature uses keys[msg.sender])
        bytes memory data = abi.encodePacked("test message");
        uint256 message = uint256(keccak256(data));
        uint256 sig = message ^ key;

        // Call isValidSignature as the caller (since keys are indexed by msg.sender)
        vm.prank(caller);
        bytes4 result = signer.isValidSignature(data, abi.encode(sig));
        assertEq(result, signer.isValidSignature.selector, "Valid signature should return magic");

        // Invalid signature should fail
        vm.prank(caller);
        bytes4 badResult = signer.isValidSignature(data, abi.encode(sig + 1));
        assertEq(badResult, bytes4(0), "Invalid signature should return 0");
    }

    // =========================================================================
    // Singleton signer factory CREATE2 address prediction
    // =========================================================================

    function test_singletonSigners_factoryAddressPrediction() public {
        TestSingletonSignerFactory factory = new TestSingletonSignerFactory();

        // Deploy a signer and verify address matches prediction
        address predicted = factory.getSigner(42);
        factory.deploySigner(42);

        assertGt(predicted.code.length, 0, "Signer should be deployed at predicted address");

        // Verify different indices give different addresses
        address predicted2 = factory.getSigner(43);
        assertTrue(predicted != predicted2, "Different indices should give different addresses");
    }

    // =========================================================================
    // Staked factory delegation
    // =========================================================================

    function test_stakedFactory_delegatesToProxyFactory() public {
        // Create a proxy through the staked factory
        bytes memory setupData = _buildBasicSetupData(_singleOwner(vm.addr(USER_PK)), 1);

        // Call createProxyWithNonce through the staked factory
        (bool success, bytes memory result) = address(stakedFactory).call(
            abi.encodeWithSignature(
                "createProxyWithNonce(address,bytes,uint256)",
                address(safeSingleton),
                setupData,
                uint256(200)
            )
        );
        assertTrue(success, "Staked factory should delegate call successfully");

        address proxyAddress = abi.decode(result, (address));
        assertGt(proxyAddress.code.length, 0, "Proxy should be deployed");
    }

    // =========================================================================
    // Internal Helpers
    // =========================================================================

    /**
     * @dev Builds Safe contract signatures for all custom signers using XOR scheme.
     *      Signers are sorted by address. Each signer uses contract signature format (v=0).
     */
    function _buildCustomSignatures(bytes32 opHash) internal view returns (bytes memory) {
        // Sort signers by address
        address[] memory sorted = new address[](NUM_SIGNERS);
        uint256[] memory sortedKeys = new uint256[](NUM_SIGNERS);
        for (uint256 i = 0; i < NUM_SIGNERS; i++) {
            sorted[i] = customSignerAddrs[i];
            sortedKeys[i] = customSignerKeys[i];
        }
        for (uint256 i = 0; i < NUM_SIGNERS; i++) {
            for (uint256 j = i + 1; j < NUM_SIGNERS; j++) {
                if (sorted[i] > sorted[j]) {
                    (sorted[i], sorted[j]) = (sorted[j], sorted[i]);
                    (sortedKeys[i], sortedKeys[j]) = (sortedKeys[j], sortedKeys[i]);
                }
            }
        }

        // Build contract signatures
        // Static parts: NUM_SIGNERS * 65 bytes
        // Dynamic parts: for each, 32 bytes length + 32 bytes XOR data
        uint256 staticSize = NUM_SIGNERS * 65;
        bytes memory staticParts;
        bytes memory dynamicParts;

        for (uint256 i = 0; i < NUM_SIGNERS; i++) {
            uint256 dynamicOffset = staticSize + dynamicParts.length;

            staticParts = abi.encodePacked(
                staticParts,
                bytes32(uint256(uint160(sorted[i]))),
                bytes32(dynamicOffset),
                uint8(0)
            );

            // XOR-based signature: signature = message ^ key
            uint256 xorSig = uint256(opHash) ^ sortedKeys[i];
            dynamicParts = abi.encodePacked(
                dynamicParts,
                bytes32(uint256(32)), // length of signature data
                bytes32(xorSig)       // the XOR signature
            );
        }

        return abi.encodePacked(staticParts, dynamicParts);
    }

    function _predictSafeAddress(bytes memory setupData, uint256 salt) internal view returns (address) {
        bytes memory proxyCreationCode = proxyFactory.proxyCreationCode();
        bytes memory deploymentData = abi.encodePacked(proxyCreationCode, uint256(uint160(address(safeSingleton))));
        bytes32 create2Salt = keccak256(abi.encodePacked(keccak256(setupData), salt));
        return address(uint160(uint256(keccak256(abi.encodePacked(
            bytes1(0xff), address(proxyFactory), create2Salt, keccak256(deploymentData)
        )))));
    }

    function _buildBasicSetupData(address[] memory owners, uint256 _threshold) internal view returns (bytes memory) {
        address[] memory modules = new address[](1);
        modules[0] = address(module);
        return abi.encodeWithSignature(
            "setup(address[],uint256,address,bytes,address,address,uint256,address)",
            owners,
            _threshold,
            address(safeModuleSetup),
            abi.encodeWithSignature("enableModules(address[])", modules),
            address(module),
            address(0),
            0,
            address(0)
        );
    }

    function _singleOwner(address owner) internal pure returns (address[] memory) {
        address[] memory owners = new address[](1);
        owners[0] = owner;
        return owners;
    }

    function _packGasLimits(uint128 verificationGasLimit, uint128 callGasLimit) internal pure returns (bytes32) {
        return bytes32(uint256(verificationGasLimit) << 128 | uint256(callGasLimit));
    }

    function _packGasFees(uint128 maxPriorityFeePerGas, uint128 maxFeePerGas) internal pure returns (bytes32) {
        return bytes32(uint256(maxPriorityFeePerGas) << 128 | uint256(maxFeePerGas));
    }

    receive() external payable {}
}

contract SingletonOpDataHelper {
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
