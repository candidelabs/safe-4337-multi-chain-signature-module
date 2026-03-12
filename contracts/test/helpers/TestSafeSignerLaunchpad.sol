// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.28;

import {IAccount} from "@account-abstraction/contracts/interfaces/IAccount.sol";
import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {_packValidationData} from "@account-abstraction/contracts/core/Helpers.sol";
import {SafeStorage} from "@safe-global/safe-contracts/contracts/libraries/SafeStorage.sol";
import {IUniqueSignerFactory} from "./TestUniqueSigner.sol";

/**
 * @title TestSafeSignerLaunchpad - Launchpad for deploying Safes with custom unique signers.
 * @dev Mirrors the reference safe-modules TestSafeSignerLaunchpad.sol contract.
 *      Used for ERC-4337 account deployment where the signer is created during the first user operation.
 */
contract TestSafeSignerLaunchpad is IAccount, SafeStorage {
    bytes32 private constant DOMAIN_SEPARATOR_TYPEHASH = keccak256("EIP712Domain(uint256 chainId,address verifyingContract)");

    // keccak256("SafeSignerLaunchpad.initHash") - 1
    uint256 private constant INIT_HASH_SLOT = 0x1d2f0b9dbb6ed3f829c9614e6c5d2ea2285238801394dc57e8500e0e306d8f80;

    bytes32 private constant SAFE_INIT_TYPEHASH =
        keccak256(
            "SafeInit(address singleton,address signerFactory,bytes signerData,address setupTo,bytes setupData,address fallbackHandler)"
        );

    bytes32 private constant SAFE_INIT_OP_TYPEHASH =
        keccak256("SafeInitOp(bytes32 userOpHash,uint48 validAfter,uint48 validUntil,address entryPoint)");

    address private immutable SELF;
    address public immutable SUPPORTED_ENTRYPOINT;

    constructor(address entryPoint) {
        require(entryPoint != address(0), "Invalid entry point");
        SELF = address(this);
        SUPPORTED_ENTRYPOINT = entryPoint;
    }

    modifier onlyProxy() {
        require(singleton == SELF, "Not called from proxy");
        _;
    }

    modifier onlySupportedEntryPoint() {
        require(msg.sender == SUPPORTED_ENTRYPOINT, "Unsupported entry point");
        _;
    }

    receive() external payable {}

    function preValidationSetup(bytes32 initHash, address to, bytes calldata preInit) external onlyProxy {
        require(_initHash() == bytes32(0), "Already initialized");
        _setInitHash(initHash);
        if (to != address(0)) {
            (bool success, ) = to.delegatecall(preInit);
            require(success, "Pre-initialization failed");
        }
    }

    function getInitHash(
        address _singleton,
        address signerFactory,
        bytes memory signerData,
        address setupTo,
        bytes memory setupData,
        address fallbackHandler
    ) public view returns (bytes32 initHash) {
        initHash = keccak256(
            abi.encodePacked(
                bytes1(0x19),
                bytes1(0x01),
                _domainSeparator(),
                keccak256(
                    abi.encode(
                        SAFE_INIT_TYPEHASH,
                        _singleton,
                        signerFactory,
                        keccak256(signerData),
                        setupTo,
                        keccak256(setupData),
                        fallbackHandler
                    )
                )
            )
        );
    }

    function getOperationHash(bytes32 userOpHash, uint48 validAfter, uint48 validUntil) public view returns (bytes32 operationHash) {
        operationHash = keccak256(_getOperationData(userOpHash, validAfter, validUntil));
    }

    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external override onlyProxy onlySupportedEntryPoint returns (uint256 validationData) {
        address signerFactory;
        bytes memory signerData;
        {
            require(this.initializeThenUserOp.selector == bytes4(userOp.callData[:4]), "invalid user operation data");

            address _singleton;
            address setupTo;
            bytes memory setupData;
            address fallbackHandler;
            (_singleton, signerFactory, signerData, setupTo, setupData, fallbackHandler, ) = abi.decode(
                userOp.callData[4:],
                (address, address, bytes, address, bytes, address, bytes)
            );
            bytes32 initHash = getInitHash(_singleton, signerFactory, signerData, setupTo, setupData, fallbackHandler);
            require(initHash == _initHash(), "invalid init hash");
        }

        validationData = _validateSignatures(userOp, userOpHash, signerFactory, signerData);
        if (missingAccountFunds > 0) {
            assembly ("memory-safe") {
                pop(call(gas(), caller(), missingAccountFunds, 0, 0, 0, 0))
            }
        }
    }

    function _validateSignatures(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        address signerFactory,
        bytes memory signerData
    ) internal view returns (uint256 validationData) {
        uint48 validAfter;
        uint48 validUntil;
        bytes calldata signature;
        {
            bytes calldata sig = userOp.signature;
            validAfter = uint48(bytes6(sig[0:6]));
            validUntil = uint48(bytes6(sig[6:12]));
            signature = sig[12:];
        }

        bytes memory operationData = _getOperationData(userOpHash, validAfter, validUntil);
        bytes32 operationHash = keccak256(operationData);
        try IUniqueSignerFactory(signerFactory).isValidSignatureForSigner(operationHash, signature, signerData) returns (
            bytes4 magicValue
        ) {
            validationData = _packValidationData(
                magicValue != IUniqueSignerFactory.isValidSignatureForSigner.selector,
                validUntil,
                validAfter
            );
        } catch {
            validationData = _packValidationData(true, validUntil, validAfter);
        }
    }

    function initializeThenUserOp(
        address _singleton,
        address signerFactory,
        bytes calldata signerData,
        address setupTo,
        bytes calldata setupData,
        address fallbackHandler,
        bytes memory callData
    ) external onlySupportedEntryPoint {
        SafeStorage.singleton = _singleton;
        {
            address[] memory _owners = new address[](1);
            _owners[0] = IUniqueSignerFactory(signerFactory).createSigner(signerData);
            SafeSetup(address(this)).setup(_owners, 1, setupTo, setupData, fallbackHandler, address(0), 0, payable(address(0)));
        }

        (bool success, bytes memory returnData) = address(this).delegatecall(callData);
        if (!success) {
            assembly ("memory-safe") {
                revert(add(returnData, 0x20), mload(returnData))
            }
        }

        _setInitHash(0);
    }

    function _domainSeparator() internal view returns (bytes32) {
        return keccak256(abi.encode(DOMAIN_SEPARATOR_TYPEHASH, block.chainid, SELF));
    }

    function _getOperationData(
        bytes32 userOpHash,
        uint48 validAfter,
        uint48 validUntil
    ) internal view returns (bytes memory operationData) {
        operationData = abi.encodePacked(
            bytes1(0x19),
            bytes1(0x01),
            _domainSeparator(),
            keccak256(abi.encode(SAFE_INIT_OP_TYPEHASH, userOpHash, validAfter, validUntil, SUPPORTED_ENTRYPOINT))
        );
    }

    function _initHash() public view returns (bytes32 value) {
        assembly ("memory-safe") {
            value := sload(INIT_HASH_SLOT)
        }
    }

    function _setInitHash(bytes32 value) internal {
        assembly ("memory-safe") {
            sstore(INIT_HASH_SLOT, value)
        }
    }
}

interface SafeSetup {
    function setup(
        address[] calldata _owners,
        uint256 _threshold,
        address to,
        bytes calldata data,
        address fallbackHandler,
        address paymentToken,
        uint256 payment,
        address payable paymentReceiver
    ) external;
}
