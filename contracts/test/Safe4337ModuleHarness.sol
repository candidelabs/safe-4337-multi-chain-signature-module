// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.28;

import {Safe4337MultiChainSignatureModule} from "../Safe4337MultiChainSignatureModule.sol";
import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {calldataKeccak, calldataKeccakWithSuffix, paymasterDataKeccak} from "@account-abstraction/contracts/core/Helpers.sol";
import {UserOperationLib} from "@account-abstraction/contracts/core/UserOperationLib.sol";

/**
 * @title Test harness that exposes internal functions for unit testing.
 * @dev Private functions (_hashPair, _efficientHash) are reimplemented identically
 *      since they cannot be inherited.
 */
contract Safe4337ModuleHarness is Safe4337MultiChainSignatureModule {
    using UserOperationLib for bytes;

    constructor(address entryPoint) Safe4337MultiChainSignatureModule(entryPoint) {}

    function exposed_hashPair(bytes32 a, bytes32 b) external pure returns (bytes32) {
        return a < b ? _exposed_efficientHash(a, b) : _exposed_efficientHash(b, a);
    }

    function _exposed_efficientHash(bytes32 a, bytes32 b) internal pure returns (bytes32 value) {
        assembly {
            mstore(0x00, a)
            mstore(0x20, b)
            value := keccak256(0x00, 0x40)
        }
    }

    function exposed_getSafeOp(
        PackedUserOperation calldata userOp
    ) external view returns (
        bytes memory operationData,
        bytes calldata proof,
        uint8 merkleTreeDepth,
        uint48 validAfter,
        uint48 validUntil,
        bytes calldata signatures
    ) {
        return _getSafeOp(userOp);
    }

    function exposed_checkSignaturesLength(
        bytes calldata signatures,
        uint256 threshold
    ) external pure returns (bool) {
        return _checkSignaturesLength(signatures, threshold);
    }

    function exposed_validateSignatures(
        PackedUserOperation calldata userOp
    ) external view returns (uint256 validationData) {
        return _validateSignatures(userOp);
    }

    function exposed_paymasterDataKeccak(bytes calldata data) external pure returns (bytes32) {
        return paymasterDataKeccak(data);
    }

    function exposed_getPaymasterSignatureLength(bytes calldata paymasterAndData) external pure returns (uint256) {
        return paymasterAndData.getPaymasterSignatureLength();
    }

    function exposed_calldataKeccak(bytes calldata data) external pure returns (bytes32) {
        return calldataKeccak(data);
    }

    function exposed_calldataKeccakWithSuffix(bytes calldata data, uint256 len, bytes8 suffix) external pure returns (bytes32) {
        return calldataKeccakWithSuffix(data, len, suffix);
    }
}
