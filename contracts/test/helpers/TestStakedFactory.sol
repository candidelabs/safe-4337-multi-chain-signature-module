// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.28;

import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";

/**
 * @title TestStakedFactory - A factory proxy that delegates calls to an underlying factory and can stake on the EntryPoint.
 * @dev Mirrors the reference safe-modules TestStakedFactory.sol contract.
 */
contract TestStakedFactory {
    address public immutable FACTORY;

    constructor(address factory) payable {
        require(factory != address(0), "Invalid factory");
        FACTORY = factory;
    }

    // solhint-disable-next-line payable-fallback,no-complex-fallback
    fallback() external {
        (bool success, bytes memory result) = FACTORY.call(msg.data);
        if (success) {
            assembly ("memory-safe") {
                return(add(result, 32), mload(result))
            }
        } else {
            assembly ("memory-safe") {
                revert(add(result, 32), mload(result))
            }
        }
    }

    function stakeEntryPoint(IEntryPoint entryPoint, uint32 unstakeDelaySecs) external payable {
        entryPoint.addStake{value: msg.value}(unstakeDelaySecs);
    }
}
