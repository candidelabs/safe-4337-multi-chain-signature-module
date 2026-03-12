// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {MockSafe} from "./MockSafe.sol";
import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {EntryPoint} from "@account-abstraction/contracts/core/EntryPoint.sol";
import {Safe4337MultiChainSignatureModule} from "../Safe4337MultiChainSignatureModule.sol";

// =========================================================================
// Minimal ERC20 for gas benchmarks
// =========================================================================
contract TestERC20 {
    string public constant name = "Test Token";
    string public constant symbol = "TST";
    uint8 public constant decimals = 18;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    uint256 public totalSupply;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        totalSupply += amount;
        emit Transfer(address(0), to, amount);
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "Insufficient balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
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
}

// =========================================================================
// Minimal ERC721 for gas benchmarks
// =========================================================================
contract TestERC721 {
    string public constant name = "Test NFT";
    string public constant symbol = "TNFT";

    mapping(uint256 => address) public ownerOf;
    mapping(address => uint256) public balanceOf;
    uint256 public nextTokenId;

    event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);

    function mint(address to) external returns (uint256 tokenId) {
        tokenId = nextTokenId++;
        ownerOf[tokenId] = to;
        balanceOf[to]++;
        emit Transfer(address(0), to, tokenId);
    }

    function transferFrom(address from, address to, uint256 tokenId) external {
        require(ownerOf[tokenId] == from, "Not owner");
        require(msg.sender == from, "Not authorized");
        ownerOf[tokenId] = to;
        balanceOf[from]--;
        balanceOf[to]++;
        emit Transfer(from, to, tokenId);
    }
}

/**
 * @title Gas Metering Tests
 * @notice Mirrors the test scenarios from safe-modules reference tests:
 *   - Gas.spec.ts: Gas benchmarks for native ETH transfers, ERC20 transfers, ERC721 minting
 * @dev These tests execute operations through the real EntryPoint and measure gas costs.
 *      Run with `forge test --match-contract GasMeteringTest -vvv --gas-report` for detailed gas reports.
 */
contract GasMeteringTest is Test {
    EntryPoint internal entryPoint;
    Safe4337MultiChainSignatureModule internal module;
    GasOpDataHelper internal opDataHelper;
    address internal relayer;

    TestERC20 internal token;
    TestERC721 internal nft;

    uint256 internal constant SIGNER_PK = 0xA11CE;

    address[] internal signers;
    uint256[] internal pks;

    function setUp() public {
        entryPoint = new EntryPoint();
        module = new Safe4337MultiChainSignatureModule(address(entryPoint));
        opDataHelper = new GasOpDataHelper(module);
        relayer = makeAddr("relayer");

        address signer = vm.addr(SIGNER_PK);
        signers.push(signer);
        pks.push(SIGNER_PK);

        token = new TestERC20();
        nft = new TestERC721();
    }

    // =========================================================================
    // Gas - Native ETH Transfer via handleOps
    // Ref: Gas.spec.ts "native transfer"
    // =========================================================================

    function test_gas_nativeTransfer() public {
        (MockSafe safe, uint256[] memory safePks) = _deploySafe();
        vm.deal(address(safe), 10 ether);

        address receiver = makeAddr("receiver");

        PackedUserOperation memory userOp = _buildUserOp(
            address(safe), 0, receiver, 1 ether, ""
        );
        userOp = _signUserOp(userOp, safePks);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        vm.prank(relayer, relayer);
        entryPoint.handleOps(ops, payable(relayer));

        assertEq(address(receiver).balance, 1 ether, "Receiver should have 1 ETH");
    }

    function test_gas_nativeTransfer_withDeposit() public {
        (MockSafe safe, uint256[] memory safePks) = _deploySafe();
        entryPoint.depositTo{value: 2 ether}(address(safe));
        vm.deal(address(safe), 1 ether);

        address receiver = makeAddr("receiver");

        PackedUserOperation memory userOp = _buildUserOp(
            address(safe), 0, receiver, 1 ether, ""
        );
        userOp = _signUserOp(userOp, safePks);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        vm.prank(relayer, relayer);
        entryPoint.handleOps(ops, payable(relayer));

        assertEq(address(receiver).balance, 1 ether, "Receiver should have 1 ETH");
    }

    // =========================================================================
    // Gas - ERC20 Token Transfer via handleOps
    // Ref: Gas.spec.ts "ERC-20 token transfer"
    // =========================================================================

    function test_gas_erc20Transfer() public {
        (MockSafe safe, uint256[] memory safePks) = _deploySafe();
        vm.deal(address(safe), 10 ether);

        address receiver = makeAddr("receiver");

        // Mint tokens to the Safe
        token.mint(address(safe), 1000e18);
        assertEq(token.balanceOf(address(safe)), 1000e18);

        // Build calldata for token.transfer(receiver, 100e18)
        bytes memory transferData = abi.encodeWithSelector(
            TestERC20.transfer.selector, receiver, 100e18
        );

        PackedUserOperation memory userOp = _buildUserOp(
            address(safe), 0, address(token), 0, transferData
        );
        userOp = _signUserOp(userOp, safePks);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        vm.prank(relayer, relayer);
        entryPoint.handleOps(ops, payable(relayer));

        assertEq(token.balanceOf(receiver), 100e18, "Receiver should have 100 tokens");
        assertEq(token.balanceOf(address(safe)), 900e18, "Safe should have 900 tokens");
    }

    function test_gas_erc20Approve_andTransferFrom() public {
        (MockSafe safe, uint256[] memory safePks) = _deploySafe();
        vm.deal(address(safe), 10 ether);

        address spender = makeAddr("spender");
        address receiver = makeAddr("receiver");

        token.mint(address(safe), 1000e18);

        // Step 1: Approve spender
        bytes memory approveData = abi.encodeWithSelector(
            TestERC20.approve.selector, spender, 500e18
        );
        PackedUserOperation memory userOp = _buildUserOp(
            address(safe), 0, address(token), 0, approveData
        );
        userOp = _signUserOp(userOp, safePks);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        vm.prank(relayer, relayer);
        entryPoint.handleOps(ops, payable(relayer));

        assertEq(token.allowance(address(safe), spender), 500e18);

        // Step 2: TransferFrom by spender
        vm.prank(spender);
        token.transferFrom(address(safe), receiver, 200e18);

        assertEq(token.balanceOf(receiver), 200e18);
        assertEq(token.balanceOf(address(safe)), 800e18);
    }

    // =========================================================================
    // Gas - ERC721 Token Minting via handleOps
    // Ref: Gas.spec.ts "ERC-721 token minting"
    // =========================================================================

    function test_gas_erc721Mint() public {
        (MockSafe safe, uint256[] memory safePks) = _deploySafe();
        vm.deal(address(safe), 10 ether);

        // Build calldata for nft.mint(safe)
        bytes memory mintData = abi.encodeWithSelector(
            TestERC721.mint.selector, address(safe)
        );

        PackedUserOperation memory userOp = _buildUserOp(
            address(safe), 0, address(nft), 0, mintData
        );
        userOp = _signUserOp(userOp, safePks);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        vm.prank(relayer, relayer);
        entryPoint.handleOps(ops, payable(relayer));

        assertEq(nft.ownerOf(0), address(safe), "Safe should own token 0");
        assertEq(nft.balanceOf(address(safe)), 1, "Safe should have 1 NFT");
    }

    function test_gas_erc721MultipleMints() public {
        (MockSafe safe, uint256[] memory safePks) = _deploySafe();
        vm.deal(address(safe), 10 ether);

        bytes memory mintData = abi.encodeWithSelector(
            TestERC721.mint.selector, address(safe)
        );

        // Mint 3 NFTs in separate user ops
        PackedUserOperation[] memory ops = new PackedUserOperation[](3);
        for (uint256 i = 0; i < 3; i++) {
            PackedUserOperation memory userOp = _buildUserOp(
                address(safe), i, address(nft), 0, mintData
            );
            userOp = _signUserOp(userOp, safePks);
            ops[i] = userOp;
        }

        vm.prank(relayer, relayer);
        entryPoint.handleOps(ops, payable(relayer));

        assertEq(nft.balanceOf(address(safe)), 3, "Safe should own 3 NFTs");
        for (uint256 i = 0; i < 3; i++) {
            assertEq(nft.ownerOf(i), address(safe));
        }
    }

    // =========================================================================
    // Gas - executeUserOpWithErrorString variant
    // =========================================================================

    function test_gas_nativeTransfer_withErrorString() public {
        (MockSafe safe, uint256[] memory safePks) = _deploySafe();
        vm.deal(address(safe), 10 ether);

        address receiver = makeAddr("receiver");

        PackedUserOperation memory userOp = _buildUserOpWithErrorString(
            address(safe), 0, receiver, 1 ether, ""
        );
        userOp = _signUserOp(userOp, safePks);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        vm.prank(relayer, relayer);
        entryPoint.handleOps(ops, payable(relayer));

        assertEq(address(receiver).balance, 1 ether);
    }

    function test_gas_erc20Transfer_withErrorString() public {
        (MockSafe safe, uint256[] memory safePks) = _deploySafe();
        vm.deal(address(safe), 10 ether);

        address receiver = makeAddr("receiver");
        token.mint(address(safe), 1000e18);

        bytes memory transferData = abi.encodeWithSelector(
            TestERC20.transfer.selector, receiver, 100e18
        );

        PackedUserOperation memory userOp = _buildUserOpWithErrorString(
            address(safe), 0, address(token), 0, transferData
        );
        userOp = _signUserOp(userOp, safePks);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        vm.prank(relayer, relayer);
        entryPoint.handleOps(ops, payable(relayer));

        assertEq(token.balanceOf(receiver), 100e18);
    }

    // =========================================================================
    // Gas - Multi-sig operations
    // =========================================================================

    function test_gas_nativeTransfer_multiSig_2of3() public {
        uint256 pk2 = 0xB0B;
        uint256 pk3 = 0xCA1;
        address s1 = vm.addr(SIGNER_PK);
        address s2 = vm.addr(pk2);
        address s3 = vm.addr(pk3);

        // Sort signers
        address[3] memory addrs = [s1, s2, s3];
        uint256[3] memory allPks = [SIGNER_PK, pk2, pk3];
        for (uint256 i = 0; i < 3; i++) {
            for (uint256 j = i + 1; j < 3; j++) {
                if (addrs[i] > addrs[j]) {
                    (addrs[i], addrs[j]) = (addrs[j], addrs[i]);
                    (allPks[i], allPks[j]) = (allPks[j], allPks[i]);
                }
            }
        }

        address[] memory owners = new address[](3);
        uint256[] memory ownerPks = new uint256[](3);
        for (uint256 i = 0; i < 3; i++) {
            owners[i] = addrs[i];
            ownerPks[i] = allPks[i];
        }

        MockSafe safe = new MockSafe(owners, 2);
        safe.setFallbackHandler(address(module));
        vm.deal(address(safe), 10 ether);

        address receiver = makeAddr("receiver");

        PackedUserOperation memory userOp = _buildUserOp(
            address(safe), 0, receiver, 1 ether, ""
        );
        // Sign with first 2 keys
        bytes memory opData = opDataHelper.getOpData(userOp);
        bytes32 opHash = keccak256(opData);
        bytes memory sigs;
        for (uint256 i = 0; i < 2; i++) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPks[i], opHash);
            sigs = abi.encodePacked(sigs, r, s, v);
        }
        userOp.signature = abi.encodePacked(uint8(0), uint48(0), uint48(0), sigs);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        vm.prank(relayer, relayer);
        entryPoint.handleOps(ops, payable(relayer));

        assertEq(address(receiver).balance, 1 ether);
    }

    // =========================================================================
    // Gas - Multi-chain merkle proof
    // =========================================================================

    function test_gas_multiChain_nativeTransfer() public {
        (MockSafe safe, uint256[] memory safePks) = _deploySafe();
        vm.deal(address(safe), 10 ether);

        address receiver = makeAddr("receiver");

        PackedUserOperation memory userOp = _buildUserOp(
            address(safe), 0, receiver, 1 ether, ""
        );

        // Build merkle tree: [leaf, otherLeaf]
        bytes memory opData = opDataHelper.getOpData(userOp);
        bytes32 leaf = keccak256(opData);
        bytes32 otherLeaf = keccak256("other_chain_op");
        bytes32 root = _hashPair(leaf, otherLeaf);
        bytes memory proof = abi.encodePacked(root, otherLeaf);

        bytes32 merkleRootHash = _merkleRootEIP712Hash(root);
        bytes memory signatures = _signHash(merkleRootHash, safePks, 1);

        userOp.signature = abi.encodePacked(uint8(1), uint48(0), uint48(0), proof, signatures);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        vm.prank(relayer, relayer);
        entryPoint.handleOps(ops, payable(relayer));

        assertEq(address(receiver).balance, 1 ether);
    }

    function test_gas_multiChain_erc20Transfer() public {
        (MockSafe safe, uint256[] memory safePks) = _deploySafe();
        vm.deal(address(safe), 10 ether);

        address receiver = makeAddr("receiver");
        token.mint(address(safe), 1000e18);

        bytes memory transferData = abi.encodeWithSelector(
            TestERC20.transfer.selector, receiver, 100e18
        );

        PackedUserOperation memory userOp = _buildUserOp(
            address(safe), 0, address(token), 0, transferData
        );

        bytes memory opData = opDataHelper.getOpData(userOp);
        bytes32 leaf = keccak256(opData);
        bytes32 otherLeaf = keccak256("other_chain_erc20_op");
        bytes32 root = _hashPair(leaf, otherLeaf);
        bytes memory proof = abi.encodePacked(root, otherLeaf);

        bytes32 merkleRootHash = _merkleRootEIP712Hash(root);
        bytes memory signatures = _signHash(merkleRootHash, safePks, 1);

        userOp.signature = abi.encodePacked(uint8(1), uint48(0), uint48(0), proof, signatures);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        vm.prank(relayer, relayer);
        entryPoint.handleOps(ops, payable(relayer));

        assertEq(token.balanceOf(receiver), 100e18);
    }

    // =========================================================================
    // Gas - Batch operations
    // =========================================================================

    function test_gas_batchNativeTransfers() public {
        (MockSafe safe, uint256[] memory safePks) = _deploySafe();
        vm.deal(address(safe), 10 ether);

        address r1 = makeAddr("receiver1");
        address r2 = makeAddr("receiver2");
        address r3 = makeAddr("receiver3");

        PackedUserOperation[] memory ops = new PackedUserOperation[](3);

        PackedUserOperation memory op0 = _buildUserOp(address(safe), 0, r1, 0.1 ether, "");
        ops[0] = _signUserOp(op0, safePks);

        PackedUserOperation memory op1 = _buildUserOp(address(safe), 1, r2, 0.2 ether, "");
        ops[1] = _signUserOp(op1, safePks);

        PackedUserOperation memory op2 = _buildUserOp(address(safe), 2, r3, 0.3 ether, "");
        ops[2] = _signUserOp(op2, safePks);

        vm.prank(relayer, relayer);
        entryPoint.handleOps(ops, payable(relayer));

        assertEq(r1.balance, 0.1 ether);
        assertEq(r2.balance, 0.2 ether);
        assertEq(r3.balance, 0.3 ether);
    }

    function test_gas_batchMixedOperations() public {
        (MockSafe safe, uint256[] memory safePks) = _deploySafe();
        vm.deal(address(safe), 10 ether);
        token.mint(address(safe), 1000e18);

        address receiver = makeAddr("receiver");

        // Op 0: Native ETH transfer
        PackedUserOperation memory op0 = _buildUserOp(address(safe), 0, receiver, 1 ether, "");
        op0 = _signUserOp(op0, safePks);

        // Op 1: ERC20 transfer
        bytes memory transferData = abi.encodeWithSelector(
            TestERC20.transfer.selector, receiver, 100e18
        );
        PackedUserOperation memory op1 = _buildUserOp(address(safe), 1, address(token), 0, transferData);
        op1 = _signUserOp(op1, safePks);

        // Op 2: ERC721 mint
        bytes memory mintData = abi.encodeWithSelector(TestERC721.mint.selector, address(safe));
        PackedUserOperation memory op2 = _buildUserOp(address(safe), 2, address(nft), 0, mintData);
        op2 = _signUserOp(op2, safePks);

        PackedUserOperation[] memory ops = new PackedUserOperation[](3);
        ops[0] = op0;
        ops[1] = op1;
        ops[2] = op2;

        vm.prank(relayer, relayer);
        entryPoint.handleOps(ops, payable(relayer));

        assertEq(receiver.balance, 1 ether);
        assertEq(token.balanceOf(receiver), 100e18);
        assertEq(nft.ownerOf(0), address(safe));
    }

    // =========================================================================
    // Internal Helpers
    // =========================================================================

    function _deploySafe() internal returns (MockSafe safe, uint256[] memory safePks) {
        address[] memory owners = new address[](1);
        owners[0] = signers[0];
        safePks = new uint256[](1);
        safePks[0] = pks[0];

        safe = new MockSafe(owners, 1);
        safe.setFallbackHandler(address(module));
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
            accountGasLimits: _packGasLimits(500000, 500000),
            preVerificationGas: 100000,
            gasFees: _packGasFees(1 gwei, 1 gwei),
            paymasterAndData: "",
            signature: abi.encodePacked(uint8(0), uint48(0), uint48(0))
        });
    }

    function _buildUserOpWithErrorString(
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
            callData: abi.encodeWithSelector(module.executeUserOpWithErrorString.selector, to, value, data, uint8(0)),
            accountGasLimits: _packGasLimits(500000, 500000),
            preVerificationGas: 100000,
            gasFees: _packGasFees(1 gwei, 1 gwei),
            paymasterAndData: "",
            signature: abi.encodePacked(uint8(0), uint48(0), uint48(0))
        });
    }

    function _signUserOp(
        PackedUserOperation memory userOp,
        uint256[] memory safePks
    ) internal view returns (PackedUserOperation memory) {
        bytes memory opData = opDataHelper.getOpData(userOp);
        bytes32 opHash = keccak256(opData);
        bytes memory signatures = _signHash(opHash, safePks, safePks.length);
        userOp.signature = abi.encodePacked(uint8(0), uint48(0), uint48(0), signatures);
        return userOp;
    }

    function _signHash(bytes32 hash, uint256[] memory safePks, uint256 count) internal view returns (bytes memory signatures) {
        for (uint256 i = 0; i < count; i++) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(safePks[i], hash);
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

    receive() external payable {}
}

/**
 * @dev Helper to convert memory UserOp to calldata for gas test operation data computation.
 */
contract GasOpDataHelper {
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
