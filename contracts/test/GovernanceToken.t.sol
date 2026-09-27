// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";

import {GovernanceToken} from "../src/GovernanceToken.sol";
import {Ownable} from "../src/base/Ownable.sol";

/// @notice Tests for `GovernanceToken`, one per upstream v2.5.6 defect.
///
/// Each test named `test_delegateVotes_*` or `test_ownership_*` is written
/// against a defect that upstream shipped; see the `// upstream v2.5.6 fix:`
/// comments in `src/GovernanceToken.sol`.
contract GovernanceTokenTest is Test {
    GovernanceToken internal token;

    address internal ownerAddr = makeAddr("owner");
    address internal alice = makeAddr("alice");
    address internal bob = makeAddr("bob");
    address internal carol = makeAddr("carol");

    /// 1_000_000 whole tokens = 1_000_000 * 10^6 minor units.
    uint256 internal constant SUPPLY = 1_000_000e6;

    function setUp() public {
        token = new GovernanceToken(ownerAddr, alice, SUPPLY);
        vm.roll(1_000);
    }

    // ---------------------------------------------------------------- baseline

    function test_decimalsMatchTheOffChainMinorUnitScale() public view {
        // money.rs: DECIMALS = 6, MINOR_UNITS_PER_MAJOR = 1_000_000.
        assertEq(uint256(token.decimals()), 6);
        assertEq(token.totalSupply(), SUPPLY);
        assertEq(token.balanceOf(alice), SUPPLY);
    }

    // ------------------------------------------- defect 1: delegateVotes reverts

    /// @dev Upstream: `votes[msg.sender] -= amount` with `votes` never
    ///      incremented — reverts for every input under checked arithmetic.
    function test_delegateVotes_actuallyAccumulatesAndMoves() public {
        // Step 1: alice delegates to herself; her own balance becomes her votes.
        vm.prank(alice);
        token.delegate(alice);
        assertEq(token.getVotes(alice), SUPPLY, "self-delegation must count the balance");
        assertEq(token.getVotes(bob), 0);

        // Step 2: alice moves the whole delegation to bob. Votes must MOVE, not
        // duplicate: the total delegated vote supply is conserved.
        vm.prank(alice);
        token.delegate(bob);
        assertEq(token.getVotes(alice), 0, "votes must leave the old delegate");
        assertEq(token.getVotes(bob), SUPPLY, "votes must arrive at the new delegate");
        assertEq(token.getVotes(alice) + token.getVotes(bob), SUPPLY);

        // Step 3: bob re-delegates to carol; the same accounting must hold.
        vm.prank(bob);
        token.delegate(carol);
        assertEq(token.getVotes(bob), 0);
        assertEq(token.getVotes(carol), SUPPLY);
    }

    function test_delegate_emitsEventsForBothSides() public {
        vm.expectEmit(true, true, true, true, address(token));
        emit GovernanceToken.DelegateChanged(alice, address(0), alice);
        vm.expectEmit(true, true, true, true, address(token));
        emit GovernanceToken.DelegateVotesChanged(alice, 0, SUPPLY);
        vm.prank(alice);
        token.delegate(alice);
    }

    function test_getPastVotes_isHistoricalNotCurrent() public {
        vm.prank(alice);
        token.delegate(alice);
        uint256 snapshotBlock = block.number;

        vm.roll(block.number + 10);
        vm.prank(alice);
        token.transfer(bob, 100e6); // alice's votes drop by 100e6
        assertEq(token.getVotes(alice), SUPPLY - 100e6);

        // The historical query must still report the old value: this is the
        // entire point of checkpointing, and upstream had no such query.
        assertEq(token.getPastVotes(alice, snapshotBlock), SUPPLY);
        assertEq(token.getPastVotes(alice, block.number - 1), SUPPLY - 100e6);
    }

    function test_getPastVotes_revertsForUnminedBlock() public {
        vm.expectRevert(GovernanceToken.BlockNotMined.selector);
        token.getPastVotes(alice, block.number);
    }

    // ------------------------------- defect 2: votes did not follow transfers

    function test_transfer_movesVotesBetweenDelegates() public {
        vm.prank(alice);
        token.delegate(alice);
        vm.prank(bob);
        token.delegate(bob);

        vm.prank(alice);
        token.transfer(bob, 250e6);

        assertEq(token.getVotes(alice), SUPPLY - 250e6);
        assertEq(token.getVotes(bob), 250e6);
        // A transfer must never create voting power.
        assertEq(token.getVotes(alice) + token.getVotes(bob), SUPPLY);
    }

    function test_undelegatedBalanceCarriesNoVotes() public {
        // Nobody delegated: the entire supply is voteless, and that is correct.
        assertEq(token.getVotes(alice), 0);
        vm.prank(alice);
        token.transfer(bob, 1e6);
        assertEq(token.getVotes(alice), 0);
        assertEq(token.getVotes(bob), 0);
    }

    function test_transferFrom_movesVotesAndSpendsAllowance() public {
        vm.prank(alice);
        token.delegate(alice);
        vm.prank(bob);
        token.delegate(bob);

        vm.prank(alice);
        token.approve(carol, 500e6);

        vm.prank(carol);
        token.transferFrom(alice, bob, 500e6);

        assertEq(token.getVotes(alice), SUPPLY - 500e6);
        assertEq(token.getVotes(bob), 500e6);
        assertEq(token.allowance(alice, carol), 0);
    }

    function test_checkpointHistoryIsBoundedByChangesNotByReceipts() public {
        vm.prank(alice);
        token.delegate(alice);
        assertEq(token.numCheckpoints(alice), 1, "self-delegation writes one checkpoint");

        // Ten receipts by an account that never delegates must append nothing to
        // the delegate history: upstream pushed a `holders` entry per first
        // receipt, which is unbounded and read by nobody.
        vm.roll(block.number + 1);
        vm.prank(alice);
        token.transfer(bob, 1e6);

        assertEq(token.numCheckpoints(alice), 2, "one checkpoint per balance change");
        assertEq(token.numCheckpoints(bob), 0, "no delegation, no checkpoints");
    }

    function test_multipleChangesInOneBlockCollapseIntoOneCheckpoint() public {
        vm.prank(alice);
        token.delegate(alice);
        uint256 afterDelegate = token.numCheckpoints(alice);

        vm.startPrank(alice);
        token.transfer(bob, 1e6);
        token.transfer(bob, 1e6);
        token.transfer(bob, 1e6);
        vm.stopPrank();

        assertEq(
            token.numCheckpoints(alice),
            afterDelegate,
            "same-block changes must overwrite, not append, or the binary search loses ordering"
        );
        assertEq(token.getVotes(alice), SUPPLY - 3e6);
    }

    // ------------------------------------ defect 3: onlyOwner was never applied

    function test_mint_revertsForNonOwner() public {
        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(Ownable.NotOwner.selector, bob));
        token.mint(bob, 1e6);
    }

    function test_mint_succeedsForOwner() public {
        vm.prank(ownerAddr);
        token.mint(carol, 5e6);
        assertEq(token.balanceOf(carol), 5e6);
        assertEq(token.totalSupply(), SUPPLY + 5e6);
    }

    /// @dev Upstream declared `onlyOwner` and had no transfer path whatsoever.
    function test_ownership_isTwoStep() public {
        // Step 1: propose. Authority must NOT move yet.
        vm.prank(ownerAddr);
        token.transferOwnership(bob);
        assertEq(token.owner(), ownerAddr, "proposal alone must not transfer authority");
        assertEq(token.pendingOwner(), bob);

        // A stranger cannot accept a proposal made to someone else.
        vm.prank(carol);
        vm.expectRevert(abi.encodeWithSelector(Ownable.NotPendingOwner.selector, carol));
        token.acceptOwnership();

        // Step 2: the nominee accepts.
        vm.prank(bob);
        token.acceptOwnership();
        assertEq(token.owner(), bob);
        assertEq(token.pendingOwner(), address(0));

        // The old owner's authority is gone.
        vm.prank(ownerAddr);
        vm.expectRevert(abi.encodeWithSelector(Ownable.NotOwner.selector, ownerAddr));
        token.mint(alice, 1e6);
    }

    function test_delegateBySig_revertsForImpersonator() public {
        vm.prank(carol);
        vm.expectRevert(GovernanceToken.InvalidDelegate.selector);
        token.delegateBySig(alice, carol);
    }

    function test_clockIsBlockNumber() public view {
        assertEq(uint256(token.clock()), block.number);
        assertEq(token.CLOCK_MODE(), "mode=blocknumber&from=default");
    }
}
