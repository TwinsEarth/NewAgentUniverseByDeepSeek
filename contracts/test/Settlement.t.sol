// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, Vm} from "forge-std/Test.sol";

import {Settlement} from "../src/Settlement.sol";
import {Ownable} from "../src/base/Ownable.sol";
import {ReentrancyGuard} from "../src/base/ReentrancyGuard.sol";

/// @notice Cooperative receiver: accepts ETH and can call back on request.
contract CooperativeReceiver {
    Settlement internal immutable settlement;
    bool internal reenter = true;

    constructor(Settlement settlement_) {
        settlement = settlement_;
    }

    function setReenter(bool value) external {
        reenter = value;
    }

    function withdraw(uint256 amount) external {
        settlement.withdrawCredits(address(this), amount, abi.encodeCall(this.onWithdraw, ()));
    }

    /// @dev Invoked with a non-empty `data` argument, so the payout travels a
    ///      call into a contract that tries to withdraw again from inside it.
    function onWithdraw() external {
        if (reenter) {
            settlement.withdrawCredits(address(this), 1, "");
        }
    }

    receive() external payable {}
}

/// @notice Tests for `Settlement`, one per upstream v2.5.6 defect.
///
/// The upstream contract was `PoCVSettlement.sol`; every defect listed in the
/// task brief has at least one test whose name says which one it covers.
contract SettlementTest is Test {
    Settlement internal settlement;

    address internal ownerAddr = makeAddr("owner");
    address internal requester = makeAddr("requester");
    address internal executor = makeAddr("executor");
    address internal stranger = makeAddr("stranger");
    address internal verifierOne = makeAddr("verifier1");
    address internal verifierTwo = makeAddr("verifier2");

    bytes32 internal constant TASK = keccak256("task-1");
    uint256 internal constant REWARD = 100e6; // 100 NAU in minor units
    uint256 internal constant STAKE = 10e6; // 10 NAU in minor units

    function setUp() public {
        address[] memory verifiers = new address[](2);
        verifiers[0] = verifierOne;
        verifiers[1] = verifierTwo;
        settlement = new Settlement(ownerAddr, verifiers, 2, 16, STAKE);

        vm.deal(requester, 1_000 ether);
        vm.deal(executor, 1_000 ether);
        vm.deal(stranger, 1_000 ether);
        vm.roll(1_000);
    }

    // ------------------------------------------------------------------ helpers
    //
    // Each helper walks the state machine one step further than the last, so a
    // test can start from the exact status it is about.

    /// @dev `Open`, reward escrowed, no executor.
    function _createOpen() internal {
        vm.prank(requester);
        settlement.createTask{value: REWARD}(TASK, REWARD);
    }

    /// @dev `Matched`, stake posted by `stranger` (the stand-in executor).
    function _matched() internal {
        _createOpen();
        vm.prank(stranger);
        settlement.acceptTask{value: STAKE}(TASK);
    }

    /// @dev `Submitted`.
    function _submitted() internal {
        _matched();
        vm.prank(stranger);
        settlement.submitResult(TASK);
    }

    /// @dev `Verified`, by a quorum of two distinct verifiers.
    function _verified() internal {
        _submitted();
        vm.prank(verifierOne);
        settlement.attestVerified(TASK);
        vm.prank(verifierTwo);
        settlement.attestVerified(TASK);
        assertEq(uint256(settlement.tasks(TASK).status), uint256(Settlement.Status.Verified));
    }

    // --------------------------- defect: createTask was payable and never read

    function test_createTask_revertsWhenMsgValueDoesNotEqualReward() public {
        vm.prank(requester);
        vm.expectRevert(
            abi.encodeWithSelector(
                Settlement.RewardMustEqualMsgValue.selector, REWARD, uint256(0)
            )
        );
        settlement.createTask(TASK, REWARD); // no value at all

        vm.prank(requester);
        vm.expectRevert(
            abi.encodeWithSelector(
                Settlement.RewardMustEqualMsgValue.selector, REWARD, REWARD - 1
            )
        );
        settlement.createTask{value: REWARD - 1}(TASK, REWARD); // underfunded

        vm.prank(requester);
        vm.expectRevert(
            abi.encodeWithSelector(
                Settlement.RewardMustEqualMsgValue.selector, REWARD, REWARD + 1
            )
        );
        settlement.createTask{value: REWARD + 1}(TASK, REWARD); // overfunded
    }

    /// @dev The upstream proof of insolvency: an unfundable maximum reward.
    function test_createTask_cannotPromiseMoreThanItEscrows() public {
        uint256 absurdReward = type(uint256).max;

        vm.prank(requester);
        vm.expectRevert(
            abi.encodeWithSelector(
                Settlement.RewardMustEqualMsgValue.selector, absurdReward, uint256(0)
            )
        );
        settlement.createTask(TASK, absurdReward);

        // And a zero-reward task is refused outright: a task that pays nobody is
        // not a task.
        vm.prank(requester);
        vm.expectRevert(Settlement.RewardMustBePositive.selector);
        settlement.createTask(TASK, 0);
    }

    function test_createTask_escrowsTheRewardExactly() public {
        uint256 balanceBefore = requester.balance;
        _createOpen();

        assertEq(requester.balance, balanceBefore - REWARD);
        assertEq(address(settlement).balance, REWARD);
        assertEq(settlement.lockedEscrow(), REWARD);
        assertEq(settlement.totalCreditsLocked(), 0);
        assertTrue(settlement.isSolvent());
    }

    function test_createTask_revertsOnDuplicateId() public {
        _createOpen();
        vm.prank(requester);
        vm.expectRevert(abi.encodeWithSelector(Settlement.TaskExists.selector, TASK));
        settlement.createTask{value: REWARD}(TASK, REWARD);
    }

    // ------------------ defect: verifyTask had no access control / no quorum

    function test_verifyTask_revertsForNonVerifier() public {
        _submitted();

        // Upstream let anyone flip this to Verified and unlock the payout.
        vm.prank(stranger);
        vm.expectRevert(
            abi.encodeWithSelector(Settlement.NotAVerifier.selector, stranger)
        );
        settlement.attestVerified(TASK);

        assertEq(uint256(settlement.tasks(TASK).status), uint256(Settlement.Status.Submitted));
    }

    function test_verifyTask_requiresAQuorumOfDistinctVerifiers() public {
        _submitted();

        // One attestation is not a quorum of two.
        vm.prank(verifierOne);
        settlement.attestVerified(TASK);
        assertEq(
            uint256(settlement.tasks(TASK).status),
            uint256(Settlement.Status.Submitted),
            "a single verifier must not reach Verified when the quorum is 2"
        );

        // The same verifier repeating itself is not a second attestation.
        vm.prank(verifierOne);
        vm.expectRevert(
            abi.encodeWithSelector(Settlement.AlreadyAttested.selector, TASK, verifierOne)
        );
        settlement.attestVerified(TASK);

        vm.prank(verifierTwo);
        settlement.attestVerified(TASK);
        assertEq(uint256(settlement.tasks(TASK).status), uint256(Settlement.Status.Verified));
    }

    function test_addVerifier_revertsForNonOwner_andHonoursCap() public {
        // Owner-only: upstream's `addVerifier` was `onlyVerifier`, so any
        // verifier could mint unlimited verifiers.
        vm.prank(verifierOne);
        vm.expectRevert(abi.encodeWithSelector(Ownable.NotOwner.selector, verifierOne));
        settlement.addVerifier(stranger);

        // Cap: the constructor-set `maxVerifiers` is 16 and two are seeded.
        vm.startPrank(ownerAddr);
        for (uint160 i = 0; i < 14; ++i) {
            settlement.addVerifier(address(uint160(0x1000 + i)));
        }
        assertEq(settlement.verifierCount(), 16);

        vm.expectRevert(abi.encodeWithSelector(Settlement.TooManyVerifiers.selector, uint256(16)));
        settlement.addVerifier(address(uint160(0x9999)));
        vm.stopPrank();

        // Removal works and frees a slot, which upstream had no way to do.
        vm.prank(ownerAddr);
        settlement.removeVerifier(address(uint160(0x1000)));
        assertEq(settlement.verifierCount(), 15);
        assertFalse(settlement.isVerifier(address(uint160(0x1000))));
    }

    // --------------------------------- defect: disputeTask had no access control

    function test_disputeTask_revertsForStranger() public {
        _submitted();

        // Upstream let any address freeze any task's funds by disputing it.
        vm.prank(stranger);
        vm.expectRevert(
            abi.encodeWithSelector(Settlement.NotRequesterOrExecutor.selector, stranger)
        );
        settlement.disputeTask(TASK);
        assertEq(uint256(settlement.tasks(TASK).status), uint256(Settlement.Status.Submitted));
    }

    function test_disputeTask_isAllowedForRequesterAndExecutor() public {
        _submitted();
        vm.prank(requester);
        settlement.disputeTask(TASK);
        assertEq(uint256(settlement.tasks(TASK).status), uint256(Settlement.Status.Disputed));
    }

    // ------------------------------------- defect: acceptTask allowed self-dealing

    function test_acceptTask_revertsForRequester() public {
        _createOpen();

        // Upstream allowed the requester to occupy both sides of the task.
        vm.prank(requester);
        vm.expectRevert(
            abi.encodeWithSelector(Settlement.RequesterCannotExecute.selector, requester)
        );
        settlement.acceptTask{value: 0}(TASK);
    }

    function test_assignTask_refusesToNameTheRequester() public {
        _createOpen();
        vm.prank(requester);
        vm.expectRevert(
            abi.encodeWithSelector(Settlement.RequesterCannotExecute.selector, requester)
        );
        settlement.assignTask(TASK, requester);

        // Naming somebody else is fine; that executor then posts the stake.
        vm.prank(requester);
        settlement.assignTask(TASK, executor);
        assertEq(settlement.tasks(TASK).executor, executor);

        vm.prank(executor);
        settlement.acceptTask{value: STAKE}(TASK);
        assertEq(uint256(settlement.tasks(TASK).status), uint256(Settlement.Status.Matched));
        assertEq(settlement.lockedEscrow(), REWARD + STAKE);
    }

    function test_acceptTask_revertsOnIncorrectStake() public {
        _createOpen();
        vm.prank(executor);
        vm.expectRevert(abi.encodeWithSelector(Settlement.IncorrectStake.selector, STAKE, STAKE + 1));
        settlement.acceptTask{value: STAKE + 1}(TASK);
    }

    function test_submitResult_isExecutorOnly() public {
        _matched();
        vm.prank(stranger);
        vm.expectRevert(
            abi.encodeWithSelector(Settlement.NotRequesterOrExecutor.selector, stranger)
        );
        settlement.submitResult(TASK);
    }

    // ----------------------------------- defect: payout to address(0)

    function test_settleTask_revertsWhenNoExecutorIsAssigned() public {
        _createOpen();
        // `createTask` leaves the task `Open` with `executor == address(0)`.
        // Settlement is refused before the executor guard is even reached, so
        // there is no state in which a payout could be addressed to zero.
        assertEq(settlement.tasks(TASK).executor, address(0));
        vm.prank(ownerAddr);
        vm.expectRevert(
            abi.encodeWithSelector(
                Settlement.InvalidStatusTransition.selector,
                TASK,
                Settlement.Status.Open,
                Settlement.Status.Settled
            )
        );
        settlement.settleTask(TASK);

        // And once matched, `settleTask` is still refused until a quorum has
        // verified the result, so an unverified task cannot be paid.
        _submitted();
        vm.prank(ownerAddr);
        vm.expectRevert(
            abi.encodeWithSelector(
                Settlement.InvalidStatusTransition.selector,
                TASK,
                Settlement.Status.Submitted,
                Settlement.Status.Settled
            )
        );
        settlement.settleTask(TASK);
    }

    function test_settleTask_requiresVerifiedStatus() public {
        _submitted();
        vm.prank(ownerAddr);
        vm.expectRevert(
            abi.encodeWithSelector(
                Settlement.InvalidStatusTransition.selector,
                TASK,
                Settlement.Status.Submitted,
                Settlement.Status.Settled
            )
        );
        settlement.settleTask(TASK);
    }

    // ------------------- defect: misbehaviour was as profitable as success

    function test_dispute_canSlashExecutor() public {
        _verified();
        vm.prank(requester);
        settlement.disputeTask(TASK);

        uint256 requesterBefore = requester.balance;

        // Slashing must be an explicit, owner-executed ruling...
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(Ownable.NotOwner.selector, stranger));
        settlement.resolveDispute(TASK, Settlement.DisputeResolution.SlashExecutor);

        vm.prank(ownerAddr);
        settlement.resolveDispute(TASK, Settlement.DisputeResolution.SlashExecutor);

        // ...and it must actually move the executor's stake to the requester.
        assertEq(
            uint256(settlement.tasks(TASK).status),
            uint256(Settlement.Status.Slashed),
            "a slash must be its own terminal status, not a full payout"
        );
        assertEq(settlement.credits(requester), REWARD + STAKE, "escrow plus the stake");
        assertEq(settlement.credits(executor), 0, "a slashed executor is paid nothing");
        assertEq(settlement.lockedEscrow(), 0);
        assertTrue(settlement.isSolvent());

        // The money is pullable, not pushed.
        vm.prank(requester);
        settlement.withdrawAllCredits(requester);
        assertEq(requester.balance, requesterBefore + REWARD + STAKE);
        assertEq(address(settlement).balance, 0);
    }

    function test_dispute_canRefundRequester_andReturnsTheStake() public {
        _verified();
        vm.prank(executor);
        settlement.disputeTask(TASK);

        vm.prank(ownerAddr);
        settlement.resolveDispute(TASK, Settlement.DisputeResolution.RefundRequester);

        assertEq(uint256(settlement.tasks(TASK).status), uint256(Settlement.Status.Refunded));
        assertEq(settlement.credits(requester), REWARD);
        assertEq(settlement.credits(executor), STAKE, "the stake is not forfeited on a plain refund");
        assertEq(settlement.lockedEscrow(), 0);
        assertTrue(settlement.isSolvent());
    }

    function test_dispute_canPayExecutor() public {
        _verified();
        vm.prank(requester);
        settlement.disputeTask(TASK);

        vm.prank(ownerAddr);
        settlement.resolveDispute(TASK, Settlement.DisputeResolution.PayExecutor);

        assertEq(uint256(settlement.tasks(TASK).status), uint256(Settlement.Status.Settled));
        assertEq(settlement.credits(executor), REWARD + STAKE);
        assertEq(settlement.credits(requester), 0);
        assertEq(settlement.lockedEscrow(), 0);
        assertTrue(settlement.isSolvent());
    }

    /// @dev The upstream defect in one assertion: a disputed task paid in full.
    function test_slashedExecutorEarnsLessThanASuccessfulOne() public {
        // Path A: honest success.
        _verified();
        vm.prank(ownerAddr);
        settlement.settleTask(TASK);
        uint256 honestPayout = settlement.credits(stranger);

        // Path B: same task shape, but slashed after a dispute.
        bytes32 secondTask = keccak256("task-2");
        address secondExecutor = makeAddr("executor2");
        vm.deal(secondExecutor, 1_000 ether);
        vm.prank(requester);
        settlement.createTask{value: REWARD}(secondTask, REWARD);
        vm.prank(secondExecutor);
        settlement.acceptTask{value: STAKE}(secondTask);
        vm.prank(secondExecutor);
        settlement.submitResult(secondTask);
        vm.prank(verifierOne);
        settlement.attestVerified(secondTask);
        vm.prank(verifierTwo);
        settlement.attestVerified(secondTask);
        vm.prank(requester);
        settlement.disputeTask(secondTask);
        vm.prank(ownerAddr);
        settlement.resolveDispute(secondTask, Settlement.DisputeResolution.SlashExecutor);

        uint256 slashedPayout = settlement.credits(secondExecutor);
        assertEq(honestPayout, REWARD + STAKE);
        assertEq(slashedPayout, 0);
        assertLt(slashedPayout, honestPayout, "misbehaviour must not pay as well as success");
    }

    function test_resolveDispute_revertsForNonDisputedTask() public {
        _verified();
        vm.prank(ownerAddr);
        vm.expectRevert(
            abi.encodeWithSelector(
                Settlement.InvalidStatusTransition.selector,
                TASK,
                Settlement.Status.Verified,
                Settlement.Status.Settled
            )
        );
        settlement.resolveDispute(TASK, Settlement.DisputeResolution.PayExecutor);
    }

    // ------------------ defect: external call before state, no reentrancy guard

    /// @dev Upstream `settleTask` pushed ETH with `call{value: payout}` before
    ///      updating `totalStaked`, so a re-entering receiver replayed the payout.
    ///      Here `settleTask` makes no external call at all and is nonetheless
    ///      guarded, and `withdrawCredits` debits before it transfers, so the
    ///      inner attempt reverts and drags the whole withdrawal down with it,
    ///      paying the attacker nothing.
    function test_settleTask_cannotReenter() public {
        CooperativeReceiver receiver = new CooperativeReceiver(settlement);
        vm.deal(address(receiver), 1_000 ether);

        // The receiver funds a task, so it is owed an escrow refund and is the
        // contract that will re-enter from inside its own payout.
        vm.prank(address(receiver));
        settlement.createTask{value: REWARD}(TASK, REWARD);

        // Path 1: the state machine itself. Settling writes state and pushes
        // nothing, so let the receiver execute a full happy path and prove that
        // settlement reaches a consistent state with no external interaction.
        bytes32 secondTask = keccak256("task-reentrancy");
        vm.prank(address(receiver));
        settlement.createTask{value: REWARD}(secondTask, REWARD);
        vm.prank(address(receiver));
        settlement.acceptTask{value: STAKE}(secondTask);
        vm.prank(address(receiver));
        settlement.submitResult(secondTask);
        vm.prank(verifierOne);
        settlement.attestVerified(secondTask);
        vm.prank(verifierTwo);
        settlement.attestVerified(secondTask);
        vm.prank(ownerAddr);
        settlement.settleTask(secondTask);
        assertEq(
            settlement.credits(address(receiver)),
            REWARD + REWARD + STAKE,
            "escrow refund plus the settled reward and stake"
        );
        assertEq(settlement.lockedEscrow(), REWARD, "only the unfunded task's escrow remains");
        assertTrue(settlement.isSolvent());

        // Path 2: the pull. The receiver re-enters `withdrawCredits` from inside
        // its own payout; the inner call hits the guard and reverts the outer
        // call, because credit was already debited before the transfer.
        vm.expectRevert(ReentrancyGuard.ReentrantCall.selector);
        receiver.withdraw(REWARD + STAKE);

        // Nothing was paid out: reentrancy bought the attacker exactly nothing.
        assertEq(settlement.credits(address(receiver)), REWARD + REWARD + STAKE);
        assertEq(address(receiver).balance, 1_000 ether);

        // A cooperative receiver (no re-entry) can still be paid normally.
        receiver.setReenter(false);
        receiver.withdraw(REWARD + STAKE);
        assertEq(address(receiver).balance, 1_000 ether + REWARD + STAKE);
        assertEq(settlement.credits(address(receiver)), REWARD);
        assertTrue(settlement.isSolvent());

        // The remaining escrow belongs to the never-matched task and is still
        // the receiver's to reclaim.
        vm.prank(address(receiver));
        settlement.refundTask(TASK);
        receiver.setReenter(false);
        vm.prank(address(receiver));
        settlement.withdrawCredits(address(receiver), REWARD, "");
        assertEq(address(settlement).balance, 0, "fully drained");
    }

    function test_withdrawCredits_rejectsOverWithdrawal() public {
        _verified();
        vm.prank(ownerAddr);
        settlement.settleTask(TASK);

        vm.prank(stranger);
        vm.expectRevert(
            abi.encodeWithSelector(
                Settlement.InsufficientCredit.selector, stranger, REWARD + STAKE + 1, REWARD + STAKE
            )
        );
        settlement.withdrawCredits(stranger, REWARD + STAKE + 1, "");

        vm.prank(stranger);
        vm.expectRevert(Settlement.NothingToWithdraw.selector);
        settlement.withdrawCredits(stranger, 0, "");

        // A third party cannot spend somebody else's credit.
        vm.prank(executor);
        vm.expectRevert(
            abi.encodeWithSelector(Settlement.InsufficientCredit.selector, executor, uint256(1), uint256(0))
        );
        settlement.withdrawCredits(executor, 1, "");
    }

    function test_settleTask_creditsExecutorAndLeavesNoEscrow() public {
        _verified();
        vm.prank(ownerAddr);
        settlement.settleTask(TASK);

        assertEq(uint256(settlement.tasks(TASK).status), uint256(Settlement.Status.Settled));
        assertEq(settlement.credits(stranger), REWARD + STAKE);
        assertEq(settlement.totalCreditsLocked(), REWARD + STAKE);
        assertEq(settlement.lockedEscrow(), 0);
        assertTrue(settlement.isSolvent());
    }

    // ---------------------------------------------- defect: totalStaked was dead

    function test_requiredStakeIsTheOnlyStakeAccounting() public {
        // `totalStaked` is gone: it was written and never read. Stake accounting
        // now lives on the task record and in `lockedEscrow`, which is checked
        // by `isSolvent`.
        _matched();
        assertEq(settlement.lockedEscrow(), REWARD + STAKE);

        _submitted();
        vm.prank(verifierOne);
        settlement.attestVerified(TASK);
        vm.prank(verifierTwo);
        settlement.attestVerified(TASK);
        vm.prank(ownerAddr);
        settlement.settleTask(TASK);

        assertEq(settlement.lockedEscrow(), 0);
        assertTrue(settlement.isSolvent());
    }

    // ---------------------------------------------------- status table coverage

    function test_refundTask_returnsEscrowToRequesterAndStakeToExecutor() public {
        _matched();
        uint256 before = requester.balance;

        vm.prank(executor);
        vm.expectRevert(
            abi.encodeWithSelector(Settlement.NotRequesterOrExecutor.selector, executor)
        );
        settlement.refundTask(TASK);

        vm.prank(requester);
        settlement.refundTask(TASK);

        assertEq(uint256(settlement.tasks(TASK).status), uint256(Settlement.Status.Refunded));
        assertEq(settlement.credits(requester), REWARD);
        assertEq(settlement.credits(stranger), STAKE);
        assertEq(settlement.lockedEscrow(), 0);

        vm.prank(requester);
        settlement.withdrawAllCredits(requester);
        assertEq(requester.balance, before + REWARD);
        assertTrue(settlement.isSolvent());
    }

    function test_refundTask_cannotEscapeADispute() public {
        _verified();
        vm.prank(requester);
        settlement.disputeTask(TASK);

        // A disputed task must be ruled on, not unilaterally abandoned.
        vm.prank(requester);
        vm.expectRevert(
            abi.encodeWithSelector(
                Settlement.InvalidStatusTransition.selector,
                TASK,
                Settlement.Status.Disputed,
                Settlement.Status.Refunded
            )
        );
        settlement.refundTask(TASK);
    }

    function test_settledTaskIsTerminal() public {
        _verified();
        vm.prank(ownerAddr);
        settlement.settleTask(TASK);

        vm.prank(requester);
        vm.expectRevert(
            abi.encodeWithSelector(
                Settlement.InvalidStatusTransition.selector,
                TASK,
                Settlement.Status.Settled,
                Settlement.Status.Disputed
            )
        );
        settlement.disputeTask(TASK);

        vm.prank(ownerAddr);
        vm.expectRevert(
            abi.encodeWithSelector(
                Settlement.InvalidStatusTransition.selector,
                TASK,
                Settlement.Status.Settled,
                Settlement.Status.Settled
            )
        );
        settlement.settleTask(TASK);
    }

    function test_unknownTaskReverts() public {
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(Settlement.TaskUnknown.selector, TASK));
        settlement.disputeTask(TASK);
    }

    function test_onlyOwnerCanConfigureQuorumAndStake() public {
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(Ownable.NotOwner.selector, stranger));
        settlement.setQuorum(1);

        vm.prank(ownerAddr);
        vm.expectRevert(abi.encodeWithSelector(Settlement.QuorumTooHigh.selector, uint32(3), uint256(2)));
        settlement.setQuorum(3);

        vm.prank(ownerAddr);
        settlement.setRequiredStake(0);
        assertEq(settlement.requiredStake(), 0);

        vm.prank(ownerAddr);
        settlement.setQuorum(1);
        assertEq(settlement.quorum(), 1);
    }

    // -------------------------------------------------------------- invariants

    /// @dev The required invariant: the contract always holds at least every
    ///      unwithdrawn credit plus every live escrow.
    function invariant_settlementIsSolvent() public view {
        assertGe(
            address(settlement).balance,
            settlement.totalCreditsLocked() + settlement.lockedEscrow(),
            "balance must cover credits + open escrows"
        );
        assertTrue(settlement.isSolvent());
    }

    /// @dev Conservation across a full happy path: nothing is created or lost.
    function testFuzz_settlementConservesValue(uint256 reward, uint256 stake) public {
        // Minor units, bounded so that two escrows cannot overflow the 1_000 ether
        // the test funds. The bound is part of the test's premise, not of the
        // contract's rules.
        reward = bound(reward, 1, 100e6);
        stake = bound(stake, 1, 10e6);

        vm.prank(ownerAddr);
        settlement.setRequiredStake(stake);

        uint256 contractBalanceBefore = address(settlement).balance;

        vm.prank(requester);
        settlement.createTask{value: reward}(TASK, reward);
        vm.prank(stranger);
        settlement.acceptTask{value: stake}(TASK);
        vm.prank(stranger);
        settlement.submitResult(TASK);
        vm.prank(verifierOne);
        settlement.attestVerified(TASK);
        vm.prank(verifierTwo);
        settlement.attestVerified(TASK);
        vm.prank(ownerAddr);
        settlement.settleTask(TASK);

        // The books: escrow is empty, both credits together equal what came in.
        assertEq(settlement.lockedEscrow(), 0, "no escrow may be left behind");
        assertEq(
            settlement.totalCreditsLocked(),
            reward + stake,
            "credits must equal the total deposited"
        );
        assertEq(settlement.credits(stranger), reward + stake);
        assertEq(
            address(settlement).balance,
            contractBalanceBefore + reward + stake,
            "the contract holds exactly what was deposited"
        );
        assertTrue(settlement.isSolvent());

        // Pull it all out and the contract must be exactly empty.
        vm.prank(stranger);
        settlement.withdrawAllCredits(stranger);
        assertEq(settlement.credits(stranger), 0);
        assertEq(settlement.totalCreditsLocked(), 0);
        assertEq(address(settlement).balance, contractBalanceBefore);
    }

    /// @dev Conservation across the refund path, where the stake goes back to the
    ///      executor rather than being forfeited.
    function testFuzz_refundConservesValue(uint256 reward, uint256 stake) public {
        reward = bound(reward, 1, 100e6);
        stake = bound(stake, 1, 10e6);

        vm.prank(ownerAddr);
        settlement.setRequiredStake(stake);

        vm.prank(requester);
        settlement.createTask{value: reward}(TASK, reward);
        vm.prank(stranger);
        settlement.acceptTask{value: stake}(TASK);
        vm.prank(requester);
        settlement.refundTask(TASK);

        assertEq(settlement.lockedEscrow(), 0);
        assertEq(settlement.totalCreditsLocked(), reward + stake);
        assertEq(settlement.credits(requester), reward);
        assertEq(settlement.credits(stranger), stake);

        vm.prank(requester);
        settlement.withdrawAllCredits(requester);
        vm.prank(stranger);
        settlement.withdrawAllCredits(stranger);

        assertEq(address(settlement).balance, 0, "a fully drained settlement holds nothing");
        assertEq(settlement.totalCreditsLocked(), 0);
    }
}
