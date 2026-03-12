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
import {SafeModuleSetup} from "./helpers/SafeModuleSetup.sol";

// =========================================================================
// Minimal ERC20 for bundler tests
// =========================================================================
contract BundlerTestToken {
    string public constant name = "HariWillibald Token";
    string public constant symbol = "HWT";
    uint8 public constant decimals = 18;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    uint256 public totalSupply;

    event Transfer(address indexed from, address indexed to, uint256 value);

    constructor(address initialHolder, uint256 initialSupply) {
        balanceOf[initialHolder] = initialSupply;
        totalSupply = initialSupply;
        emit Transfer(address(0), initialHolder, initialSupply);
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "Insufficient balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(balanceOf[from] >= amount, "Insufficient balance");
        require(allowance[from][msg.sender] >= amount, "Insufficient allowance");
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        emit Transfer(from, to, amount);
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }
}

/**
 * @title E2E Bundler Tests
 * @notice Mirrors test scenarios from safe-modules reference tests:
 *   - LocalBundler.spec.ts: Deploy new Safe + execute, execute on existing Safe
 * @dev Simulates the bundler flow by directly calling EntryPoint.handleOps,
 *      which is what a bundler does internally. Uses real SafeProxyFactory and SafeL2.
 */
contract E2EBundlerTest is Test {
    EntryPoint internal entryPoint;
    Safe4337MultiChainSignatureModule internal module;
    SafeProxyFactory internal proxyFactory;
    SafeL2 internal safeSingleton;
    SafeModuleSetup internal safeModuleSetup;
    BundlerTestToken internal token;
    E2EOpDataHelper internal opDataHelper;

    address internal relayer;
    uint256 internal constant USER_PK = 0xA11CE;
    address internal user;

    function setUp() public {
        entryPoint = new EntryPoint();
        module = new Safe4337MultiChainSignatureModule(address(entryPoint));
        proxyFactory = new SafeProxyFactory();
        safeSingleton = new SafeL2();
        safeModuleSetup = new SafeModuleSetup();
        opDataHelper = new E2EOpDataHelper(module);

        relayer = makeAddr("relayer");
        user = vm.addr(USER_PK);

        // Deploy token with initial supply to this test contract
        token = new BundlerTestToken(address(this), 1000000e18);
    }

    // =========================================================================
    // Deploy new Safe via initCode and execute token transfer
    // Ref: LocalBundler.spec.ts "should deploy a new Safe and execute a transaction"
    // =========================================================================

    function test_e2e_deployNewSafe_andExecuteTokenTransfer() public {
        // Compute the Safe address that will be created
        address safeAddress = _computeSafeAddress(user, 0);

        // Fund the predicted Safe address
        token.transfer(safeAddress, 42e17);
        vm.deal(safeAddress, 0.5 ether);

        // Verify Safe is not deployed yet
        assertEq(safeAddress.code.length, 0, "Safe should not be deployed yet");
        assertEq(token.balanceOf(safeAddress), 42e17);

        // Build initCode
        bytes memory initCode = _buildInitCode(user, 0);

        // Build the user operation: transfer all tokens back to user
        bytes memory transferData = abi.encodeWithSelector(
            BundlerTestToken.transfer.selector, user, token.balanceOf(safeAddress)
        );

        uint48 validAfter = uint48(0);
        uint48 validUntil = uint48(block.timestamp + 300);

        PackedUserOperation memory userOp;
        {
            userOp = PackedUserOperation({
                sender: safeAddress,
                nonce: 0,
                initCode: initCode,
                callData: abi.encodeWithSelector(module.executeUserOp.selector, address(token), 0, transferData, uint8(0)),
                accountGasLimits: _packGasLimits(700000, 500000),
                preVerificationGas: 100000,
                gasFees: _packGasFees(1 gwei, 1 gwei),
                paymasterAndData: "",
                signature: abi.encodePacked(uint8(0), validAfter, validUntil)
            });
        }

        // Sign the user operation
        {
            bytes memory opData = opDataHelper.getOpData(userOp);
            bytes32 opHash = keccak256(opData);
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(USER_PK, opHash);
            userOp.signature = abi.encodePacked(uint8(0), validAfter, validUntil, r, s, v);
        }

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        vm.prank(relayer, relayer);
        entryPoint.handleOps(ops, payable(relayer));

        // Verify Safe is deployed
        assertGt(safeAddress.code.length, 0, "Safe should be deployed");
        // Verify token transfer happened
        assertEq(token.balanceOf(safeAddress), 0, "Safe should have transferred all tokens");
        assertEq(token.balanceOf(user), 42e17, "User should have received tokens");
        // Verify Safe spent ETH on gas
        assertLt(address(safeAddress).balance, 0.5 ether, "Safe should have paid gas fees");
    }

    // =========================================================================
    // Execute on existing Safe
    // Ref: LocalBundler.spec.ts "should execute a transaction for an existing Safe"
    // =========================================================================

    function test_e2e_existingSafe_executeTokenTransfer() public {
        // Deploy Safe first
        address safeAddress = _deploySafe(user, 0);
        assertGt(safeAddress.code.length, 0, "Safe should be deployed");

        // Fund the Safe
        token.transfer(safeAddress, 42e17);
        vm.deal(safeAddress, 0.5 ether);

        assertEq(token.balanceOf(safeAddress), 42e17);

        // Build user operation (no initCode for existing Safe)
        bytes memory transferData = abi.encodeWithSelector(
            BundlerTestToken.transfer.selector, user, token.balanceOf(safeAddress)
        );

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: safeAddress,
            nonce: 0,
            initCode: "",
            callData: abi.encodeWithSelector(module.executeUserOp.selector, address(token), 0, transferData, uint8(0)),
            accountGasLimits: _packGasLimits(500000, 500000),
            preVerificationGas: 100000,
            gasFees: _packGasFees(1 gwei, 1 gwei),
            paymasterAndData: "",
            signature: abi.encodePacked(uint8(0), uint48(0), uint48(0))
        });

        // Sign
        {
            bytes memory opData = opDataHelper.getOpData(userOp);
            bytes32 opHash = keccak256(opData);
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(USER_PK, opHash);
            userOp.signature = abi.encodePacked(uint8(0), uint48(0), uint48(0), r, s, v);
        }

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        vm.prank(relayer, relayer);
        entryPoint.handleOps(ops, payable(relayer));

        assertEq(token.balanceOf(safeAddress), 0, "Safe should have transferred all tokens");
        assertEq(token.balanceOf(user), 42e17, "User should have tokens");
        assertLt(address(safeAddress).balance, 0.5 ether, "Safe should have paid gas");
    }

    // =========================================================================
    // Deploy new Safe and execute ETH transfer
    // =========================================================================

    function test_e2e_deployNewSafe_andExecuteEthTransfer() public {
        address safeAddress = _computeSafeAddress(user, 1);

        vm.deal(safeAddress, 2 ether);
        assertEq(safeAddress.code.length, 0);

        bytes memory initCode = _buildInitCode(user, 1);
        address receiver = makeAddr("receiver");

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: safeAddress,
            nonce: 0,
            initCode: initCode,
            callData: abi.encodeWithSelector(module.executeUserOp.selector, receiver, 0.5 ether, "", uint8(0)),
            accountGasLimits: _packGasLimits(700000, 500000),
            preVerificationGas: 100000,
            gasFees: _packGasFees(1 gwei, 1 gwei),
            paymasterAndData: "",
            signature: abi.encodePacked(uint8(0), uint48(0), uint48(0))
        });

        {
            bytes memory opData = opDataHelper.getOpData(userOp);
            bytes32 opHash = keccak256(opData);
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(USER_PK, opHash);
            userOp.signature = abi.encodePacked(uint8(0), uint48(0), uint48(0), r, s, v);
        }

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        vm.prank(relayer, relayer);
        entryPoint.handleOps(ops, payable(relayer));

        assertGt(safeAddress.code.length, 0, "Safe should be deployed");
        assertEq(receiver.balance, 0.5 ether, "Receiver should have ETH");
    }

    // =========================================================================
    // Deploy new Safe and execute multiple operations
    // =========================================================================

    function test_e2e_existingSafe_multipleOps() public {
        address safeAddress = _deploySafe(user, 2);
        vm.deal(safeAddress, 3 ether);
        token.transfer(safeAddress, 100e18);

        address receiver = makeAddr("receiver");

        // Op 0: ETH transfer
        PackedUserOperation memory userOp0 = PackedUserOperation({
            sender: safeAddress,
            nonce: 0,
            initCode: "",
            callData: abi.encodeWithSelector(module.executeUserOp.selector, receiver, 0.5 ether, "", uint8(0)),
            accountGasLimits: _packGasLimits(500000, 500000),
            preVerificationGas: 100000,
            gasFees: _packGasFees(1 gwei, 1 gwei),
            paymasterAndData: "",
            signature: abi.encodePacked(uint8(0), uint48(0), uint48(0))
        });
        {
            bytes32 opHash = keccak256(opDataHelper.getOpData(userOp0));
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(USER_PK, opHash);
            userOp0.signature = abi.encodePacked(uint8(0), uint48(0), uint48(0), r, s, v);
        }

        // Op 1: ERC20 transfer
        bytes memory transferData = abi.encodeWithSelector(BundlerTestToken.transfer.selector, receiver, 50e18);
        PackedUserOperation memory userOp1 = PackedUserOperation({
            sender: safeAddress,
            nonce: 1,
            initCode: "",
            callData: abi.encodeWithSelector(module.executeUserOp.selector, address(token), 0, transferData, uint8(0)),
            accountGasLimits: _packGasLimits(500000, 500000),
            preVerificationGas: 100000,
            gasFees: _packGasFees(1 gwei, 1 gwei),
            paymasterAndData: "",
            signature: abi.encodePacked(uint8(0), uint48(0), uint48(0))
        });
        {
            bytes32 opHash = keccak256(opDataHelper.getOpData(userOp1));
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(USER_PK, opHash);
            userOp1.signature = abi.encodePacked(uint8(0), uint48(0), uint48(0), r, s, v);
        }

        PackedUserOperation[] memory ops = new PackedUserOperation[](2);
        ops[0] = userOp0;
        ops[1] = userOp1;

        vm.prank(relayer, relayer);
        entryPoint.handleOps(ops, payable(relayer));

        assertEq(receiver.balance, 0.5 ether);
        assertEq(token.balanceOf(receiver), 50e18);
    }

    // =========================================================================
    // Deploy via initCode with invalid signature should revert
    // =========================================================================

    function test_e2e_deployNewSafe_invalidSignature_reverts() public {
        address safeAddress = _computeSafeAddress(user, 3);
        vm.deal(safeAddress, 2 ether);

        bytes memory initCode = _buildInitCode(user, 3);

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: safeAddress,
            nonce: 0,
            initCode: initCode,
            callData: abi.encodeWithSelector(module.executeUserOp.selector, address(0), 0, "", uint8(0)),
            accountGasLimits: _packGasLimits(700000, 500000),
            preVerificationGas: 100000,
            gasFees: _packGasFees(1 gwei, 1 gwei),
            paymasterAndData: "",
            signature: abi.encodePacked(uint8(0), uint48(0), uint48(0))
        });

        // Sign with wrong key
        {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(0xDEAD, keccak256("wrong"));
            userOp.signature = abi.encodePacked(uint8(0), uint48(0), uint48(0), r, s, v);
        }

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        vm.prank(relayer, relayer);
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error"));
        entryPoint.handleOps(ops, payable(relayer));
    }

    // =========================================================================
    // Deploy via initCode + multi-chain merkle proof
    // =========================================================================

    function test_e2e_deployNewSafe_multiChainMerkleProof() public {
        address safeAddress = _computeSafeAddress(user, 4);
        vm.deal(safeAddress, 2 ether);

        bytes memory initCode = _buildInitCode(user, 4);
        address receiver = makeAddr("receiver");

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: safeAddress,
            nonce: 0,
            initCode: initCode,
            callData: abi.encodeWithSelector(module.executeUserOp.selector, receiver, 0.5 ether, "", uint8(0)),
            accountGasLimits: _packGasLimits(700000, 500000),
            preVerificationGas: 100000,
            gasFees: _packGasFees(1 gwei, 1 gwei),
            paymasterAndData: "",
            signature: abi.encodePacked(uint8(0), uint48(0), uint48(0))
        });

        // Build merkle tree and sign
        bytes memory proof;
        bytes memory signatures;
        {
            bytes memory opData = opDataHelper.getOpData(userOp);
            bytes32 leaf = keccak256(opData);
            bytes32 otherLeaf = keccak256("other_chain_op");
            bytes32 root = _hashPair(leaf, otherLeaf);
            proof = abi.encodePacked(root, otherLeaf);

            bytes32 merkleRootHash = _merkleRootEIP712Hash(root);
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(USER_PK, merkleRootHash);
            signatures = abi.encodePacked(r, s, v);
        }

        userOp.signature = abi.encodePacked(uint8(1), uint48(0), uint48(0), proof, signatures);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        vm.prank(relayer, relayer);
        entryPoint.handleOps(ops, payable(relayer));

        assertGt(safeAddress.code.length, 0);
        assertEq(receiver.balance, 0.5 ether);
    }

    // =========================================================================
    // Existing Safe - executeUserOpWithErrorString
    // =========================================================================

    function test_e2e_existingSafe_executeWithErrorString() public {
        address safeAddress = _deploySafe(user, 5);
        vm.deal(safeAddress, 2 ether);
        token.transfer(safeAddress, 42e17);

        bytes memory transferData = abi.encodeWithSelector(
            BundlerTestToken.transfer.selector, user, token.balanceOf(safeAddress)
        );

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: safeAddress,
            nonce: 0,
            initCode: "",
            callData: abi.encodeWithSelector(module.executeUserOpWithErrorString.selector, address(token), 0, transferData, uint8(0)),
            accountGasLimits: _packGasLimits(500000, 500000),
            preVerificationGas: 100000,
            gasFees: _packGasFees(1 gwei, 1 gwei),
            paymasterAndData: "",
            signature: abi.encodePacked(uint8(0), uint48(0), uint48(0))
        });

        {
            bytes32 opHash = keccak256(opDataHelper.getOpData(userOp));
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(USER_PK, opHash);
            userOp.signature = abi.encodePacked(uint8(0), uint48(0), uint48(0), r, s, v);
        }

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        vm.prank(relayer, relayer);
        entryPoint.handleOps(ops, payable(relayer));

        assertEq(token.balanceOf(safeAddress), 0);
        assertEq(token.balanceOf(user), 42e17);
    }

    // =========================================================================
    // Verify Safe configuration after deployment
    // =========================================================================

    function test_e2e_deployNewSafe_verifiesConfiguration() public {
        address safeAddress = _computeSafeAddress(user, 6);
        vm.deal(safeAddress, 2 ether);

        bytes memory initCode = _buildInitCode(user, 6);

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: safeAddress,
            nonce: 0,
            initCode: initCode,
            callData: abi.encodeWithSelector(module.executeUserOp.selector, address(0), 0, "", uint8(0)),
            accountGasLimits: _packGasLimits(700000, 500000),
            preVerificationGas: 100000,
            gasFees: _packGasFees(1 gwei, 1 gwei),
            paymasterAndData: "",
            signature: abi.encodePacked(uint8(0), uint48(0), uint48(0))
        });

        {
            bytes32 opHash = keccak256(opDataHelper.getOpData(userOp));
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(USER_PK, opHash);
            userOp.signature = abi.encodePacked(uint8(0), uint48(0), uint48(0), r, s, v);
        }

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        vm.prank(relayer, relayer);
        entryPoint.handleOps(ops, payable(relayer));

        // Verify Safe is deployed with correct configuration
        assertGt(safeAddress.code.length, 0, "Safe should be deployed");

        SafeL2 safe = SafeL2(payable(safeAddress));
        assertEq(safe.getThreshold(), 1, "Threshold should be 1");

        address[] memory owners = safe.getOwners();
        assertEq(owners.length, 1, "Should have 1 owner");
        assertEq(owners[0], user, "Owner should be user");

        // Verify module is enabled
        (address[] memory modules,) = safe.getModulesPaginated(address(0x1), 10);
        bool moduleFound = false;
        for (uint256 i = 0; i < modules.length; i++) {
            if (modules[i] == address(module)) {
                moduleFound = true;
                break;
            }
        }
        assertTrue(moduleFound, "Module should be enabled");
    }

    // =========================================================================
    // Internal Helpers
    // =========================================================================

    function _buildSetupData(address owner) internal view returns (bytes memory) {
        address[] memory owners = new address[](1);
        owners[0] = owner;

        address[] memory modules = new address[](1);
        modules[0] = address(module);

        return abi.encodeWithSignature(
            "setup(address[],uint256,address,bytes,address,address,uint256,address)",
            owners,
            1,
            address(safeModuleSetup),
            abi.encodeWithSignature("enableModules(address[])", modules),
            address(module),
            address(0),
            0,
            address(0)
        );
    }

    function _buildInitCode(address owner, uint256 salt) internal view returns (bytes memory) {
        bytes memory setupData = _buildSetupData(owner);
        bytes memory createProxyData = abi.encodeWithSignature(
            "createProxyWithNonce(address,bytes,uint256)",
            address(safeSingleton),
            setupData,
            salt
        );
        return abi.encodePacked(address(proxyFactory), createProxyData);
    }

    function _computeSafeAddress(address owner, uint256 salt) internal view returns (address) {
        bytes memory setupData = _buildSetupData(owner);
        bytes memory proxyCreationCode = proxyFactory.proxyCreationCode();
        bytes memory deploymentData = abi.encodePacked(proxyCreationCode, uint256(uint160(address(safeSingleton))));
        bytes32 create2Salt = keccak256(abi.encodePacked(keccak256(setupData), salt));
        return address(uint160(uint256(keccak256(abi.encodePacked(
            bytes1(0xff), address(proxyFactory), create2Salt, keccak256(deploymentData)
        )))));
    }

    function _deploySafe(address owner, uint256 salt) internal returns (address) {
        bytes memory setupData = _buildSetupData(owner);
        SafeProxy proxy = proxyFactory.createProxyWithNonce(address(safeSingleton), setupData, salt);
        return address(proxy);
    }

    function _packGasLimits(uint128 verificationGasLimit, uint128 callGasLimit) internal pure returns (bytes32) {
        return bytes32(uint256(verificationGasLimit) << 128 | uint256(callGasLimit));
    }

    function _packGasFees(uint128 maxPriorityFeePerGas, uint128 maxFeePerGas) internal pure returns (bytes32) {
        return bytes32(uint256(maxPriorityFeePerGas) << 128 | uint256(maxFeePerGas));
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
 * @dev Helper to convert memory UserOp to calldata for operation data computation.
 */
contract E2EOpDataHelper {
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
