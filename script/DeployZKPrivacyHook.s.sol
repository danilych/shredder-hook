// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {ZKPrivacyHook} from "../src/ZKPrivacyHook.sol";
import {IPoolManager} from "v4-core/src/interfaces/IPoolManager.sol";
import {Hooks} from "v4-core/src/libraries/Hooks.sol";

/// @title Deploy ZK Privacy Hook
/// @notice Script to deploy the ZK Privacy Hook for Uniswap V4
contract DeployZKPrivacyHook is Script {
    // Mainnet addresses - update for different networks
    address constant POOL_MANAGER_MAINNET = 0x0000000000000000000000000000000000000000; // Update when available
    address constant POOL_MANAGER_SEPOLIA = 0x0000000000000000000000000000000000000000; // Update when available
    address constant POOL_MANAGER_LOCAL = 0x0000000000000000000000000000000000000000; // For local testing

    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address poolManager = getPoolManagerAddress();
        
        vm.startBroadcast(deployerPrivateKey);

        // Calculate hook address with correct flags
        address hookAddress = calculateHookAddress();
        
        console.log("Deploying ZK Privacy Hook to:", hookAddress);
        console.log("Pool Manager:", poolManager);

        // Deploy the hook
        ZKPrivacyHook hook = new ZKPrivacyHook{salt: bytes32(uint256(0x4444))}(
            IPoolManager(poolManager)
        );

        console.log("ZK Privacy Hook deployed at:", address(hook));
        
        // Verify the hook has correct permissions
        Hooks.Permissions memory permissions = hook.getHookPermissions();
        console.log("Hook Permissions:");
        console.log("  beforeSwap:", permissions.beforeSwap);
        console.log("  afterSwap:", permissions.afterSwap);
        console.log("  beforeSwapReturnDelta:", permissions.beforeSwapReturnDelta);

        vm.stopBroadcast();

        // Save deployment info
        saveDeploymentInfo(address(hook), poolManager);
    }

    function calculateHookAddress() internal pure returns (address) {
        // Calculate the hook address with the required flags
        uint160 flags = uint160(
            Hooks.BEFORE_SWAP_FLAG | 
            Hooks.AFTER_SWAP_FLAG | 
            Hooks.BEFORE_SWAP_RETURNS_DELTA_FLAG
        ) ^ (0x4444 << 144); // Namespace to avoid collisions
        
        return address(flags);
    }

    function getPoolManagerAddress() internal view returns (address) {
        uint256 chainId = block.chainid;
        
        if (chainId == 1) {
            // Mainnet
            return POOL_MANAGER_MAINNET;
        } else if (chainId == 11155111) {
            // Sepolia
            return POOL_MANAGER_SEPOLIA;
        } else {
            // Local or testnet
            address envPoolManager = vm.envOr("POOL_MANAGER", POOL_MANAGER_LOCAL);
            require(envPoolManager != address(0), "Pool manager address not set");
            return envPoolManager;
        }
    }

    function saveDeploymentInfo(address hookAddress, address poolManager) internal {
        string memory deploymentInfo = string(abi.encodePacked(
            "{\n",
            '  "hookAddress": "', vm.toString(hookAddress), '",\n',
            '  "poolManager": "', vm.toString(poolManager), '",\n',
            '  "chainId": ', vm.toString(block.chainid), ',\n',
            '  "timestamp": ', vm.toString(block.timestamp), '\n',
            "}"
        ));
        
        vm.writeFile("deployment.json", deploymentInfo);
        console.log("Deployment info saved to deployment.json");
    }
}

/// @title Deploy Test Environment
/// @notice Script to deploy test environment with mock pool manager
contract DeployTestEnvironment is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        
        vm.startBroadcast(deployerPrivateKey);

        // For testing, you would deploy a mock pool manager here
        // This is simplified for demonstration
        console.log("Test environment deployment not implemented");
        console.log("Use forge test for testing functionality");

        vm.stopBroadcast();
    }
}
