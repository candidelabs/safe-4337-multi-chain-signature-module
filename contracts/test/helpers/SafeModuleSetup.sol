// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.28;

import {ISafe} from "../../Safe.sol";

/**
 * @title SafeModuleSetup - Enables modules during Safe setup.
 * @dev Mirrors the reference safe-modules SafeModuleSetup.sol contract.
 *      Used as the `to` target during Safe.setup() to enable the 4337 module.
 */
contract SafeModuleSetup {
    function enableModules(address[] calldata modules) external {
        for (uint256 i = 0; i < modules.length; i++) {
            ISafe(address(this)).enableModule(modules[i]);
        }
    }
}
