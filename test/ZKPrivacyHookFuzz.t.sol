// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {ZKPrivacyHook} from "../src/ZKPrivacyHook.sol";
import {IHooks} from "v4-core/src/interfaces/IHooks.sol";
import {Hooks} from "v4-core/src/libraries/Hooks.sol";
import {IPoolManager} from "v4-core/src/interfaces/IPoolManager.sol";
import {PoolKey} from "v4-core/src/types/PoolKey.sol";
import {Currency} from "v4-core/src/types/Currency.sol";
import {IERC20} from "@openzeppelin/contracts/interfaces/IERC20.sol";
import {Fixtures} from "./utils/Fixtures.sol";

/// @title Fuzz tests for ZK Privacy Hook
/// @notice Property-based testing for edge cases and invariants
contract ZKPrivacyHookFuzzTest is Test, Fixtures {
    ZKPrivacyHook hook;
    
    address alice = address(0x1);
    address bob = address(0x2);

    function setUp() public {
        deployFreshManagerAndRouters();
        deployMintAndApprove2Currencies();

        address flags = address(
            uint160(Hooks.BEFORE_SWAP_FLAG | Hooks.AFTER_SWAP_FLAG | Hooks.BEFORE_SWAP_RETURNS_DELTA_FLAG) 
            ^ (0x4444 << 144)
        );

        deployCodeTo("ZKPrivacyHook.sol:ZKPrivacyHook", abi.encode(manager), flags);
        hook = ZKPrivacyHook(flags);

        // Setup test accounts
        deal(Currency.unwrap(currency0), alice, 10000000e18);
        deal(Currency.unwrap(currency1), alice, 10000000e18);
        deal(Currency.unwrap(currency0), bob, 10000000e18);
        deal(Currency.unwrap(currency1), bob, 10000000e18);

        vm.startPrank(alice);
        IERC20(Currency.unwrap(currency0)).approve(address(hook), type(uint256).max);
        IERC20(Currency.unwrap(currency1)).approve(address(hook), type(uint256).max);
        vm.stopPrank();

        vm.startPrank(bob);
        IERC20(Currency.unwrap(currency0)).approve(address(hook), type(uint256).max);
        IERC20(Currency.unwrap(currency1)).approve(address(hook), type(uint256).max);
        vm.stopPrank();
    }

    /// @notice Test commitment generation with random inputs
    function testFuzzCommitmentGeneration(uint256 amount, uint256 secret) public {
        // Bound inputs to valid ranges
        amount = bound(amount, 1, 1000000 * 1e18);
        secret = bound(secret, 1, type(uint256).max - 1);

        bytes32 commitment1 = hook.generateCommitment(amount, currency0, secret);
        bytes32 commitment2 = hook.generateCommitment(amount, currency0, secret);
        bytes32 commitment3 = hook.generateCommitment(amount, currency0, secret + 1);

        // Same inputs should produce same commitment
        assertEq(commitment1, commitment2);
        
        // Different secrets should produce different commitments
        assertNotEq(commitment1, commitment3);
        
        // Commitment should not be zero
        assertNotEq(commitment1, bytes32(0));
    }

    /// @notice Test nullifier generation with random inputs
    function testFuzzNullifierGeneration(bytes32 commitment, uint256 secret) public {
        vm.assume(commitment != bytes32(0));
        secret = bound(secret, 1, type(uint256).max - 1);

        bytes32 nullifier1 = hook.generateNullifier(commitment, secret);
        bytes32 nullifier2 = hook.generateNullifier(commitment, secret);
        bytes32 nullifier3 = hook.generateNullifier(commitment, secret + 1);

        // Same inputs should produce same nullifier
        assertEq(nullifier1, nullifier2);
        
        // Different secrets should produce different nullifiers
        assertNotEq(nullifier1, nullifier3);
        
        // Nullifier should not be zero
        assertNotEq(nullifier1, bytes32(0));
    }

    /// @notice Test private deposits with random amounts
    function testFuzzPrivateDeposit(uint256 amount, uint256 secret) public {
        // Bound to valid ranges
        amount = bound(amount, 1, 1000000 * 1e18);
        secret = bound(secret, 1, type(uint256).max);

        bytes32 commitment = hook.generateCommitment(amount, currency0, secret);
        
        uint256 balanceBefore = IERC20(Currency.unwrap(currency0)).balanceOf(alice);
        uint256 hookBalanceBefore = IERC20(Currency.unwrap(currency0)).balanceOf(address(hook));

        vm.prank(alice);
        hook.privateDeposit(commitment, amount, currency0);

        uint256 balanceAfter = IERC20(Currency.unwrap(currency0)).balanceOf(alice);
        uint256 hookBalanceAfter = IERC20(Currency.unwrap(currency0)).balanceOf(address(hook));

        // Invariants
        assertEq(balanceAfter, balanceBefore - amount, "User balance should decrease by amount");
        assertEq(hookBalanceAfter, hookBalanceBefore + amount, "Hook balance should increase by amount");
        assertTrue(hook.commitmentExists(commitment), "Commitment should exist");
        
        (uint256 totalDeposits,) = hook.getPrivateStats(currency0);
        assertGe(totalDeposits, amount, "Total deposits should include this amount");
    }

    /// @notice Test multiple deposits maintain correct totals
    function testFuzzMultipleDeposits(uint256[5] memory amounts, uint256[5] memory secrets) public {
        uint256 totalExpected = 0;
        
        for (uint i = 0; i < 5; i++) {
            amounts[i] = bound(amounts[i], 1, 100000 * 1e18); // Smaller bounds for multiple deposits
            secrets[i] = bound(secrets[i], 1, type(uint256).max);
            
            bytes32 commitment = hook.generateCommitment(amounts[i], currency0, secrets[i]);
            
            vm.prank(alice);
            hook.privateDeposit(commitment, amounts[i], currency0);
            
            totalExpected += amounts[i];
            assertTrue(hook.commitmentExists(commitment));
        }

        (uint256 totalDeposits,) = hook.getPrivateStats(currency0);
        assertEq(totalDeposits, totalExpected, "Total deposits should equal sum of all deposits");
    }

    /// @notice Test commitment uniqueness across different parameters
    function testFuzzCommitmentUniqueness(
        uint256 amount1, uint256 amount2,
        uint256 secret1, uint256 secret2
    ) public {
        // Bound inputs
        amount1 = bound(amount1, 1, 1000000 * 1e18);
        amount2 = bound(amount2, 1, 1000000 * 1e18);
        secret1 = bound(secret1, 1, type(uint256).max - 1);
        secret2 = bound(secret2, 1, type(uint256).max - 1);

        // Ensure inputs are different
        vm.assume(amount1 != amount2 || secret1 != secret2);

        bytes32 commitment1 = hook.generateCommitment(amount1, currency0, secret1);
        bytes32 commitment2 = hook.generateCommitment(amount2, currency0, secret2);

        // Different inputs should produce different commitments
        assertNotEq(commitment1, commitment2, "Different inputs should produce different commitments");
    }

    /// @notice Test nullifier uniqueness
    function testFuzzNullifierUniqueness(
        bytes32 commitment1, bytes32 commitment2,
        uint256 secret1, uint256 secret2
    ) public {
        vm.assume(commitment1 != bytes32(0) && commitment2 != bytes32(0));
        vm.assume(commitment1 != commitment2 || secret1 != secret2);
        
        secret1 = bound(secret1, 1, type(uint256).max - 1);
        secret2 = bound(secret2, 1, type(uint256).max - 1);

        bytes32 nullifier1 = hook.generateNullifier(commitment1, secret1);
        bytes32 nullifier2 = hook.generateNullifier(commitment2, secret2);

        // Different inputs should produce different nullifiers
        assertNotEq(nullifier1, nullifier2, "Different inputs should produce different nullifiers");
    }

    /// @notice Test private withdrawal invariants
    function testFuzzPrivateWithdraw(uint256 amount, uint256 secret) public {
        amount = bound(amount, 1, 1000000 * 1e18);
        secret = bound(secret, 1, type(uint256).max);

        bytes32 commitment = hook.generateCommitment(amount, currency0, secret);
        bytes32 nullifier = hook.generateNullifier(commitment, secret);

        // Deposit first
        vm.prank(alice);
        hook.privateDeposit(commitment, amount, currency0);

        uint256 bobBalanceBefore = IERC20(Currency.unwrap(currency0)).balanceOf(bob);
        uint256 hookBalanceBefore = IERC20(Currency.unwrap(currency0)).balanceOf(address(hook));

        // Create valid proof
        ZKPrivacyHook.ZKProof memory proof = ZKPrivacyHook.ZKProof({
            a: [uint256(1), uint256(2)],
            b: [[uint256(3), uint256(4)], [uint256(5), uint256(6)]],
            c: [uint256(7), uint256(8)],
            publicSignals: new uint256[](4)
        });
        proof.publicSignals[0] = uint256(commitment);
        proof.publicSignals[1] = secret;
        proof.publicSignals[2] = amount;

        vm.prank(alice);
        hook.privateWithdraw(nullifier, bob, amount, currency0, proof);

        uint256 bobBalanceAfter = IERC20(Currency.unwrap(currency0)).balanceOf(bob);
        uint256 hookBalanceAfter = IERC20(Currency.unwrap(currency0)).balanceOf(address(hook));

        // Invariants
        assertEq(bobBalanceAfter, bobBalanceBefore + amount, "Recipient should receive the amount");
        assertEq(hookBalanceAfter, hookBalanceBefore - amount, "Hook balance should decrease");
        assertTrue(hook.isNullifierUsed(nullifier), "Nullifier should be marked as used");
    }

    /// @notice Test that invalid amounts are rejected
    function testFuzzInvalidAmounts(uint256 amount) public {
        // Test amounts outside valid range
        vm.assume(amount == 0 || amount > 1000000 * 1e18);
        
        bytes32 commitment = hook.generateCommitment(amount, currency0, 12345);
        
        vm.expectRevert(ZKPrivacyHook.InvalidCommitment.selector);
        vm.prank(alice);
        hook.privateDeposit(commitment, amount, currency0);
    }

    /// @notice Test double spending protection
    function testFuzzDoubleSpendingProtection(uint256 amount, uint256 secret) public {
        amount = bound(amount, 1, 1000000 * 1e18);
        secret = bound(secret, 1, type(uint256).max);

        bytes32 commitment = hook.generateCommitment(amount, currency0, secret);
        bytes32 nullifier = hook.generateNullifier(commitment, secret);

        // Deposit
        vm.prank(alice);
        hook.privateDeposit(commitment, amount, currency0);

        // Create proof
        ZKPrivacyHook.ZKProof memory proof = ZKPrivacyHook.ZKProof({
            a: [uint256(1), uint256(2)],
            b: [[uint256(3), uint256(4)], [uint256(5), uint256(6)]],
            c: [uint256(7), uint256(8)],
            publicSignals: new uint256[](4)
        });
        proof.publicSignals[0] = uint256(commitment);
        proof.publicSignals[1] = secret;
        proof.publicSignals[2] = amount;

        // First withdrawal should succeed
        vm.prank(alice);
        hook.privateWithdraw(nullifier, bob, amount, currency0, proof);

        // Second withdrawal should fail
        vm.expectRevert(ZKPrivacyHook.NullifierAlreadyUsed.selector);
        vm.prank(alice);
        hook.privateWithdraw(nullifier, bob, amount, currency0, proof);
    }

    /// @notice Test commitment collision resistance with many attempts
    function testFuzzCommitmentCollisionResistance(uint256 seed) public {
        bytes32[] memory commitments = new bytes32[](50);
        
        for (uint256 i = 0; i < 50; i++) {
            uint256 amount = bound(uint256(keccak256(abi.encode(seed, i, "amount"))), 1, 1000000 * 1e18);
            uint256 secret = bound(uint256(keccak256(abi.encode(seed, i, "secret"))), 1, type(uint256).max);
            
            commitments[i] = hook.generateCommitment(amount, currency0, secret);
            
            // Check against all previous commitments
            for (uint256 j = 0; j < i; j++) {
                assertNotEq(commitments[i], commitments[j], "Commitment collision detected");
            }
        }
    }

    /// @notice Test gas usage bounds for deposits
    function testFuzzGasUsage(uint256 amount, uint256 secret) public {
        amount = bound(amount, 1, 1000000 * 1e18);
        secret = bound(secret, 1, type(uint256).max);

        bytes32 commitment = hook.generateCommitment(amount, currency0, secret);
        
        uint256 gasStart = gasleft();
        vm.prank(alice);
        hook.privateDeposit(commitment, amount, currency0);
        uint256 gasUsed = gasStart - gasleft();

        // Gas usage should be reasonable (less than 200k gas)
        assertLt(gasUsed, 200000, "Gas usage should be reasonable");
    }
}
