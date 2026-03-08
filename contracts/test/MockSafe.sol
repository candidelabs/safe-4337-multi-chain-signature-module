// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.28;

import {ISafe} from "../Safe.sol";

/**
 * @title MockSafe - A minimal Safe mock for testing the module in isolation.
 * @dev Supports configurable threshold, owner-based ECDSA signature verification,
 *      and acts as a fallback handler proxy (appends msg.sender per ERC-2771).
 */
contract MockSafe is ISafe {
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
     * @dev Validates ECDSA signatures in the Safe's packed format.
     * Each signature is 65 bytes: r (32) + s (32) + v (1).
     * Signatures must be sorted by signer address (ascending).
     */
    function checkSignatures(
        bytes32 dataHash,
        bytes memory /* data */,
        bytes memory signatures
    ) external view override {
        uint256 threshold = _threshold;
        require(signatures.length >= threshold * 65, "Signatures too short");

        address lastOwner = address(0);
        for (uint256 i = 0; i < threshold; i++) {
            (uint8 v, bytes32 r, bytes32 s) = _signatureSplit(signatures, i);

            address recovered = ecrecover(dataHash, v, r, s);
            require(recovered != address(0), "Invalid signature");
            require(_isOwner[recovered], "Not an owner");
            require(recovered > lastOwner, "Signatures not sorted");
            lastOwner = recovered;
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
     * @dev Forward calls to the fallback handler, appending msg.sender (ERC-2771 style).
     */
    fallback() external payable {
        address handler = _fallbackHandler;
        require(handler != address(0), "No fallback handler");

        // solhint-disable-next-line no-inline-assembly
        assembly {
            // Copy calldata
            calldatacopy(0, 0, calldatasize())
            // Append msg.sender (20 bytes)
            mstore(calldatasize(), shl(96, caller()))
            // Forward to handler
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
        // solhint-disable-next-line no-inline-assembly
        assembly {
            let signaturePos := mul(0x41, pos)
            r := mload(add(signatures, add(signaturePos, 0x20)))
            s := mload(add(signatures, add(signaturePos, 0x40)))
            v := byte(0, mload(add(signatures, add(signaturePos, 0x60))))
        }
    }
}
