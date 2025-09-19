// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Fixtures} from "./utils/Fixtures.sol";
import {PoolManager} from "v4-core/src/PoolManager.sol";
import {IPoolManager} from "v4-core/src/interfaces/IPoolManager.sol";
import {Deployers} from "v4-core/test/utils/Deployers.sol";
import {TestERC20} from "v4-core/src/test/TestERC20.sol";
import {CurrencyLibrary, Currency} from "v4-core/src/types/Currency.sol";
import {PoolId, PoolIdLibrary} from "v4-core/src/types/PoolId.sol";
import {StateLibrary} from "v4-core/src/libraries/StateLibrary.sol";
import {LiquidityAmounts} from "v4-core/test/utils/LiquidityAmounts.sol";
import {TickMath} from "v4-core/src/libraries/TickMath.sol";
import {IPositionManager} from "v4-periphery/src/interfaces/IPositionManager.sol";
import {EasyPosm} from "./utils/EasyPosm.sol";
import {Fixtures} from "./utils/Fixtures.sol";
import {PoolKey} from "v4-core/src/types/PoolKey.sol";
import {Hooks} from "v4-core/src/libraries/Hooks.sol";
import {IHooks} from "v4-core/src/interfaces/IHooks.sol";
import {IERC20} from "@openzeppelin/contracts/interfaces/IERC20.sol";
import {BalanceDelta} from "v4-core/src/types/BalanceDelta.sol";

import {ZKPrivacyHook} from "../src/ZKPrivacyHook.sol";
import {MockZKVerifier} from "./mocks/MockZKVerifier.sol";

contract ZKPrivacyHookTest is Test, Fixtures {
    using EasyPosm for IPositionManager;
    using PoolIdLibrary for PoolKey;
    using CurrencyLibrary for Currency;
    using StateLibrary for IPoolManager;

    ZKPrivacyHook hook;
    PoolId poolId;

    uint256 tokenId;
    int24 tickLower;
    int24 tickUpper;

    // Test accounts
    address alice = address(0x1);
    address bob = address(0x2);
    address charlie = address(0x3);

    // ZK proof test data
    ZKPrivacyHook.ZKProof mockProof;
    
    function setUp() public {
        // Create pool manager, utility routers, and test tokens
        deployFreshManagerAndRouters();
        deployMintAndApprove2Currencies();
        deployAndApprovePosm(manager);

        // Deploy the ZK privacy hook to correct address with flags
        address flags = address(
            uint160(
                Hooks.BEFORE_SWAP_FLAG | Hooks.AFTER_SWAP_FLAG | Hooks.BEFORE_SWAP_RETURNS_DELTA_FLAG
            ) ^ (0x4444 << 144) // Namespace the hook to avoid collisions
        );

        bytes memory constructorArgs = abi.encode(manager);
        deployCodeTo("ZKPrivacyHook.sol:ZKPrivacyHook", constructorArgs, flags);
        hook = ZKPrivacyHook(flags);
        
        // Deploy and set up mock verifier
        MockZKVerifier mockVerifier = new MockZKVerifier();
        mockVerifier.setAlwaysVerify(true); // Enable always verify for easier testing
        hook.setMockVerifier(address(mockVerifier));

        // Create the pool
        key = PoolKey(currency0, currency1, 3000, 60, IHooks(hook));
        poolId = key.toId();
        manager.initialize(key, SQRT_PRICE_1_1);

        // Provide full-range liquidity to the pool
        tickLower = TickMath.minUsableTick(key.tickSpacing);
        tickUpper = TickMath.maxUsableTick(key.tickSpacing);

        uint128 liquidityAmount = 100e18;

        (uint256 amount0Expected, uint256 amount1Expected) = LiquidityAmounts.getAmountsForLiquidity(
            SQRT_PRICE_1_1,
            TickMath.getSqrtPriceAtTick(tickLower),
            TickMath.getSqrtPriceAtTick(tickUpper),
            liquidityAmount
        );

        (tokenId,) = posm.mint(
            key,
            tickLower,
            tickUpper,
            liquidityAmount,
            amount0Expected + 1,
            amount1Expected + 1,
            address(this),
            block.timestamp,
            ZERO_BYTES
        );

        // Setup mock proof
        mockProof = ZKPrivacyHook.ZKProof({
            a: [uint256(1), uint256(2)],
            b: [[uint256(3), uint256(4)], [uint256(5), uint256(6)]],
            c: [uint256(7), uint256(8)],
            publicSignals: new uint256[](4)
        });

        // Mint tokens to test accounts
        deal(Currency.unwrap(currency0), alice, 10000e18);
        deal(Currency.unwrap(currency1), alice, 10000e18);
        deal(Currency.unwrap(currency0), bob, 10000e18);
        deal(Currency.unwrap(currency1), bob, 10000e18);
        deal(Currency.unwrap(currency0), charlie, 10000e18);
        deal(Currency.unwrap(currency1), charlie, 10000e18);

        // Approve hook to spend tokens
        vm.startPrank(alice);
        IERC20(Currency.unwrap(currency0)).approve(address(hook), type(uint256).max);
        IERC20(Currency.unwrap(currency1)).approve(address(hook), type(uint256).max);
        vm.stopPrank();

        vm.startPrank(bob);
        IERC20(Currency.unwrap(currency0)).approve(address(hook), type(uint256).max);
        IERC20(Currency.unwrap(currency1)).approve(address(hook), type(uint256).max);
        vm.stopPrank();
    }

    function testHookPermissions() public {
        Hooks.Permissions memory permissions = hook.getHookPermissions();
        
        assertEq(permissions.beforeSwap, true);
        assertEq(permissions.afterSwap, true);
        assertEq(permissions.beforeSwapReturnDelta, true);
        assertEq(permissions.beforeAddLiquidity, false);
        assertEq(permissions.afterAddLiquidity, false);
    }

    function testGenerateCommitment() public {
        uint256 amount = 100e18;
        uint256 secret = 12345;
        
        bytes32 commitment = hook.generateCommitment(amount, currency0, secret);
        bytes32 expectedCommitment = keccak256(abi.encodePacked(amount, currency0, secret));
        
        assertEq(commitment, expectedCommitment);
    }

    function testGenerateNullifier() public {
        bytes32 commitment = keccak256(abi.encodePacked(uint256(100e18), currency0, uint256(12345)));
        uint256 secret = 12345;
        
        bytes32 nullifier = hook.generateNullifier(commitment, secret);
        bytes32 expectedNullifier = keccak256(abi.encodePacked(commitment, secret));
        
        assertEq(nullifier, expectedNullifier);
    }

    function testPrivateDeposit() public {
        uint256 amount = 100e18;
        uint256 secret = 12345;
        bytes32 commitment = hook.generateCommitment(amount, currency0, secret);

        uint256 initialBalance = IERC20(Currency.unwrap(currency0)).balanceOf(alice);
        uint256 initialHookBalance = IERC20(Currency.unwrap(currency0)).balanceOf(address(hook));

        vm.prank(alice);
        hook.privateDeposit(commitment, amount, currency0);

        uint256 finalBalance = IERC20(Currency.unwrap(currency0)).balanceOf(alice);
        uint256 finalHookBalance = IERC20(Currency.unwrap(currency0)).balanceOf(address(hook));

        assertEq(finalBalance, initialBalance - amount);
        assertEq(finalHookBalance, initialHookBalance + amount);
        assertEq(hook.commitmentExists(commitment), true);

        (uint256 totalDeposits,) = hook.getPrivateStats(currency0);
        assertEq(totalDeposits, amount);
    }

    function testPrivateDepositInvalidCommitment() public {
        uint256 amount = 100e18;
        
        vm.expectRevert(ZKPrivacyHook.InvalidCommitment.selector);
        vm.prank(alice);
        hook.privateDeposit(bytes32(0), amount, currency0);
    }

    function testPrivateDepositZeroAmount() public {
        bytes32 commitment = keccak256(abi.encodePacked(uint256(0), currency0, uint256(12345)));
        
        vm.expectRevert(ZKPrivacyHook.InvalidCommitment.selector);
        vm.prank(alice);
        hook.privateDeposit(commitment, 0, currency0);
    }

    function testPrivateDepositDuplicateCommitment() public {
        uint256 amount = 100e18;
        uint256 secret = 12345;
        bytes32 commitment = hook.generateCommitment(amount, currency0, secret);

        vm.startPrank(alice);
        hook.privateDeposit(commitment, amount, currency0);
        
        vm.expectRevert(ZKPrivacyHook.InvalidCommitment.selector);
        hook.privateDeposit(commitment, amount, currency0);
        vm.stopPrank();
    }

    function testPrivateWithdraw() public {
        uint256 amount = 100e18;
        uint256 secret = 12345;
        bytes32 commitment = hook.generateCommitment(amount, currency0, secret);
        bytes32 nullifier = hook.generateNullifier(commitment, secret);

        // Setup mock proof for withdrawal
        mockProof.publicSignals[0] = uint256(commitment);
        mockProof.publicSignals[1] = secret;
        mockProof.publicSignals[2] = amount;

        // Deposit first
        vm.prank(alice);
        hook.privateDeposit(commitment, amount, currency0);

        uint256 initialBalance = IERC20(Currency.unwrap(currency0)).balanceOf(bob);

        // Withdraw
        vm.prank(alice);
        hook.privateWithdraw(nullifier, bob, amount, currency0, mockProof);

        uint256 finalBalance = IERC20(Currency.unwrap(currency0)).balanceOf(bob);
        assertEq(finalBalance, initialBalance + amount);
        assertEq(hook.isNullifierUsed(nullifier), true);
    }

    function testPrivateWithdrawDoubleSpending() public {
        uint256 amount = 100e18;
        uint256 secret = 12345;
        bytes32 commitment = hook.generateCommitment(amount, currency0, secret);
        bytes32 nullifier = hook.generateNullifier(commitment, secret);

        mockProof.publicSignals[0] = uint256(commitment);
        mockProof.publicSignals[1] = secret;
        mockProof.publicSignals[2] = amount;

        // Deposit first
        vm.prank(alice);
        hook.privateDeposit(commitment, amount, currency0);

        // First withdrawal
        vm.prank(alice);
        hook.privateWithdraw(nullifier, bob, amount, currency0, mockProof);

        // Second withdrawal should fail
        vm.expectRevert(ZKPrivacyHook.NullifierAlreadyUsed.selector);
        vm.prank(alice);
        hook.privateWithdraw(nullifier, charlie, amount, currency0, mockProof);
    }

    function testPrivateSwap() public {
        uint256 amount = 1e17; // Use smaller amount for testing
        uint256 secret = 12345;
        bytes32 commitment = hook.generateCommitment(amount, currency0, secret);
        bytes32 nullifier = hook.generateNullifier(commitment, secret);
        bytes32 newCommitment = keccak256(abi.encodePacked(amount, currency1, secret + 1));

        // Deposit first
        vm.prank(alice);
        hook.privateDeposit(commitment, amount, currency0);

        // Setup private swap parameters
        ZKPrivacyHook.PrivateSwapParams memory privateParams = ZKPrivacyHook.PrivateSwapParams({
            nullifierIn: nullifier,
            nullifierOut: bytes32(0),
            newCommitment: newCommitment,
            proof: mockProof,
            minAmountOut: 0
        });

        // Setup mock proof for swap
        mockProof.publicSignals[0] = uint256(commitment);
        mockProof.publicSignals[1] = secret;
        mockProof.publicSignals[2] = amount;
        mockProof.publicSignals[3] = uint256(newCommitment);

        // Mock verifier is set to always verify, no need to set specific proofs

        bytes memory hookData = abi.encode(privateParams);

        // Perform private swap
        bool zeroForOne = true;
        int256 amountSpecified = -int256(amount);
        
        BalanceDelta swapDelta = swap(key, zeroForOne, amountSpecified, hookData);

        assertEq(hook.isNullifierUsed(nullifier), true);
        assertEq(hook.commitmentExists(newCommitment), true);
        assertGt(hook.totalPrivateVolume(poolId), 0);
    }

    function testPrivateSwapInvalidProof() public {
        uint256 amount = 1e17; // Use smaller amount
        bytes32 nullifier = keccak256("invalid");
        bytes32 newCommitment = keccak256("new commitment");

        // Disable always verify for this test to actually test proof validation
        MockZKVerifier verifier = MockZKVerifier(address(hook.mockVerifier()));
        verifier.setAlwaysVerify(false);

        // Setup invalid private swap parameters
        ZKPrivacyHook.PrivateSwapParams memory privateParams = ZKPrivacyHook.PrivateSwapParams({
            nullifierIn: nullifier,
            nullifierOut: bytes32(0),
            newCommitment: newCommitment,
            proof: mockProof,
            minAmountOut: 0
        });

        // Invalid proof - publicSignals don't match (and not pre-set as valid)
        mockProof.publicSignals = new uint256[](4);
        mockProof.publicSignals[0] = uint256(keccak256("wrong commitment"));
        mockProof.publicSignals[1] = 99999; // wrong secret
        mockProof.publicSignals[2] = amount;
        mockProof.publicSignals[3] = uint256(newCommitment);

        bytes memory hookData = abi.encode(privateParams);

        bool zeroForOne = true;
        int256 amountSpecified = -int256(amount);
        
        vm.expectRevert(); // Expect any revert (will be wrapped by pool manager)
        swap(key, zeroForOne, amountSpecified, hookData);
        
        // Re-enable always verify for other tests
        verifier.setAlwaysVerify(true);
    }

    function testRegularSwapWithoutHookData() public {
        // Test that regular swaps work without hook data
        bool zeroForOne = true;
        int256 amountSpecified = -1e18;
        
        BalanceDelta swapDelta = swap(key, zeroForOne, amountSpecified, ZERO_BYTES);
        
        assertLt(swapDelta.amount0(), 0); // Spent token0
        assertGt(swapDelta.amount1(), 0); // Received token1
    }

    function testMultiplePrivateDeposits() public {
        uint256 amount1 = 100e18;
        uint256 amount2 = 200e18;
        bytes32 commitment1 = hook.generateCommitment(amount1, currency0, 111);
        bytes32 commitment2 = hook.generateCommitment(amount2, currency0, 222);

        vm.startPrank(alice);
        hook.privateDeposit(commitment1, amount1, currency0);
        hook.privateDeposit(commitment2, amount2, currency0);
        vm.stopPrank();

        assertEq(hook.commitmentExists(commitment1), true);
        assertEq(hook.commitmentExists(commitment2), true);

        (uint256 totalDeposits,) = hook.getPrivateStats(currency0);
        assertEq(totalDeposits, amount1 + amount2);
    }

    function testPrivateStatsTracking() public {
        uint256 amount = 100e18;
        bytes32 commitment = hook.generateCommitment(amount, currency1, 12345);

        (uint256 initialDeposits,) = hook.getPrivateStats(currency1);
        assertEq(initialDeposits, 0);

        vm.prank(alice);
        hook.privateDeposit(commitment, amount, currency1);

        (uint256 finalDeposits,) = hook.getPrivateStats(currency1);
        assertEq(finalDeposits, amount);
    }

    function testNullifierGeneration() public {
        bytes32 commitment1 = keccak256("commitment1");
        bytes32 commitment2 = keccak256("commitment2");
        uint256 secret = 12345;

        bytes32 nullifier1 = hook.generateNullifier(commitment1, secret);
        bytes32 nullifier2 = hook.generateNullifier(commitment2, secret);
        bytes32 nullifier3 = hook.generateNullifier(commitment1, secret + 1);

        // Different commitments should produce different nullifiers
        assertNotEq(nullifier1, nullifier2);
        // Different secrets should produce different nullifiers
        assertNotEq(nullifier1, nullifier3);
        // Same inputs should produce same nullifier
        assertEq(nullifier1, hook.generateNullifier(commitment1, secret));
    }

    function testMaxPrivateAmount() public {
        uint256 maxAmount = 1000000 * 1e18;
        uint256 tooMuchAmount = maxAmount + 1;
        
        bytes32 validCommitment = hook.generateCommitment(maxAmount, currency0, 123);
        bytes32 invalidCommitment = hook.generateCommitment(tooMuchAmount, currency0, 456);

        // Make sure alice has enough balance for max amount
        deal(Currency.unwrap(currency0), alice, maxAmount + 1000e18);

        // Max amount should work
        vm.prank(alice);
        hook.privateDeposit(validCommitment, maxAmount, currency0);

        // Above max should fail
        vm.expectRevert(ZKPrivacyHook.InvalidCommitment.selector);
        vm.prank(alice);
        hook.privateDeposit(invalidCommitment, tooMuchAmount, currency0);
    }
}
