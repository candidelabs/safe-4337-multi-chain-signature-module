// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.28;

/**
 * @title InitCode - Computes the initCode for deploying a Safe proxy with 4337 module enabled.
 * @dev Mirrors the reference safe-modules InitCode.sol contract.
 */
contract InitCode {
    struct Config {
        address safeModuleSetup;
        address erc4337module;
        address safeSingleton;
        address proxyFactory;
    }

    address public immutable SAFE_MODULE_SETUP_ADDRESS;
    address public immutable SAFE_4337_MODULE_ADDRESS;
    address public immutable SAFE_SINGLETON_ADDRESS;
    address public immutable SAFE_PROXY_FACTORY_ADDRESS;

    constructor(Config memory config) {
        SAFE_MODULE_SETUP_ADDRESS = config.safeModuleSetup;
        SAFE_4337_MODULE_ADDRESS = config.erc4337module;
        SAFE_SINGLETON_ADDRESS = config.safeSingleton;
        SAFE_PROXY_FACTORY_ADDRESS = config.proxyFactory;
    }

    function getInitCode(address[] memory _owners, uint256 _threshold, uint256 saltNonce) external view returns (bytes memory) {
        address[] memory modules = new address[](1);
        modules[0] = SAFE_4337_MODULE_ADDRESS;

        bytes memory initializer = abi.encodeWithSignature(
            "setup(address[],uint256,address,bytes,address,address,uint256,address)",
            _owners,
            _threshold,
            SAFE_MODULE_SETUP_ADDRESS,
            abi.encodeWithSignature("enableModules(address[])", modules),
            SAFE_4337_MODULE_ADDRESS,
            address(0),
            0,
            address(0)
        );

        bytes memory initCallData = abi.encodeWithSignature(
            "createProxyWithNonce(address,bytes,uint256)",
            SAFE_SINGLETON_ADDRESS,
            initializer,
            saltNonce
        );

        return abi.encodePacked(SAFE_PROXY_FACTORY_ADDRESS, initCallData);
    }
}
