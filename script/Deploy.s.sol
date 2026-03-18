// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {Safe4337MultiChainSignatureModule} from "../contracts/Safe4337MultiChainSignatureModule.sol";

contract Deploy is Script {
    /// @dev Nick's deterministic deployment proxy (ERC-2470).
    address constant DETERMINISTIC_FACTORY = 0x4e59b44847b379578588920cA78FbF26c0B4956C;

    /// @dev EntryPoint v0.9.
    address constant ENTRY_POINT = 0x433709009B8330FDa32311DF1C2AFA402eD8D009;

    function run() external {
        bytes32 salt = vm.envOr("SALT", bytes32(0));

        bytes memory creationCode = abi.encodePacked(
            type(Safe4337MultiChainSignatureModule).creationCode,
            abi.encode(ENTRY_POINT)
        );

        address predicted = vm.computeCreate2Address(salt, keccak256(creationCode), DETERMINISTIC_FACTORY);
        console.log("Predicted address:", predicted);

        if (predicted.code.length > 0) {
            console.log("Already deployed, skipping.");
            return;
        }

        vm.startBroadcast();
        Safe4337MultiChainSignatureModule module = new Safe4337MultiChainSignatureModule{salt: salt}(ENTRY_POINT);
        vm.stopBroadcast();

        require(address(module) == predicted, "Deployment address mismatch");
        console.log("Safe4337MultiChainSignatureModule deployed at:", address(module));
        console.log("EntryPoint:", ENTRY_POINT);
    }
}
