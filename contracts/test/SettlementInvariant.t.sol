// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, StdInvariant, Vm} from "forge-std/Test.sol";

import {Settlement} from "../src/Settlement.sol";

/// @notice Drives random operation sequences against `Settlement` for the
///         invariant run.
///
/// Deliberately a **plain contract**, not a `Test` subclass. A `Test` subclass
/// inherits `assertEq`, `fail`, `deal`, and the rest as *public* functions, and
/// `targetContract(address)` makes Foundry fuzz every public function on the
/// target — so a `Test`-derived handler has hundreds of non-operation entry
/// points (many of which revert by design) that the fuzzer would spend its
/// budget discovering. This contract exposes exactly the operations.
///
/// Every operation is *guarded*: it returns early unless its preconditions hold,
/// so the fuzzer is never charged with finding a legal sequence, and a revert
/// after a guard passed is a genuine finding rather than a fuzzing artifact.
contract SettlementHandler {
    Settlement public settlement;
    address public ownerAddr;

    address[] internal requesters;
    address[] internal executors;
    address[] internal verifiers;

    bytes32[] internal taskIds;
    uint256 internal nextTaskSeed;

    /// @notice Non-zero when an operation that had passed its guard still failed.
    ///         Setting it is not itself a revert, so the fuzzer records the
    ///         offending call and `invariant_noHandlerViolation` reports it.
    bytes4 public violation;

    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    constructor(
        Settlement settlement_,
        address owner_,
        address[] memory requesters_,
        address[] memory executors_,
        address[] memory verifiers_
    ) {
        settlement = settlement_;
        ownerAddr = owner_;
        requesters = requesters_;
        executors = executors_;
        verifiers = verifiers_;
    }

    receive() external payable {}

    function requestersLength() external view returns (uint256) {
        return requesters.length;
    }

    function executorsLength() external view returns (uint256) {
        return executors.length;
    }

    function verifiersLength() external view returns (uint256) {
        return verifiers.length;
    }

    function taskIdsLength() external view returns (uint256) {
        return taskIds.length;
    }

    function _record(bytes4 selector) private {
        if (violation == bytes4(0)) violation = selector;
    }

    /// @dev A fresh id every call, so the task count grows with the run and the
    ///      pool of live tasks is genuinely random.
    function _newTaskId() private returns (bytes32) {
        nextTaskSeed += 1;
        bytes32 id = keccak256(abi.encodePacked("invariant-task", nextTaskSeed));
        taskIds.push(id);
        return id;
    }

    function _pick(address[] storage pool, uint256 seed) private view returns (address) {
        return pool[seed % pool.length];
    }

    function _exists(bytes32 id) private view returns (bool) {
        return settlement.tasks(id).requester != address(0);
    }

    // ------------------------------------------------------------- operations

    function opCreate(uint256 requesterSeed, uint256 rewardSeed) external {
        address requester = _pick(requesters, requesterSeed);
        uint256 reward = 1e6 + (rewardSeed % 50e6); // 1..50 NAU in minor units
        bytes32 id = _newTaskId();

        vm.prank(requester);
        settlement.createTask{value: reward}(id, reward);
    }

    function opAcceptOpen(uint256 taskSeed, uint256 executorSeed) external {
        if (taskIds.length == 0) return;
        bytes32 id = taskIds[taskSeed % taskIds.length];
        if (!_exists(id)) return;
        if (settlement.tasks(id).status != Settlement.Status.Open) return;

        address executor = _pick(executors, executorSeed);
        if (executor == settlement.tasks(id).requester) return;

        uint256 stake = settlement.requiredStake();
        vm.prank(executor);
        settlement.acceptTask{value: stake}(id);
        if (settlement.tasks(id).status != Settlement.Status.Matched) {
            _record(this.opAcceptOpen.selector);
        }
    }

    function opAssign(uint256 taskSeed, uint256 executorSeed) external {
        if (taskIds.length == 0) return;
        bytes32 id = taskIds[taskSeed % taskIds.length];
        if (!_exists(id)) return;
        if (settlement.tasks(id).status != Settlement.Status.Open) return;

        address executor = _pick(executors, executorSeed);
        if (executor == settlement.tasks(id).requester) return;

        address requester = settlement.tasks(id).requester;
        vm.prank(requester);
        settlement.assignTask(id, executor);

        uint256 stake = settlement.requiredStake();
        vm.prank(executor);
        settlement.acceptTask{value: stake}(id);
        if (settlement.tasks(id).status != Settlement.Status.Matched) {
            _record(this.opAssign.selector);
        }
    }

    function opSubmit(uint256 taskSeed) external {
        if (taskIds.length == 0) return;
        bytes32 id = taskIds[taskSeed % taskIds.length];
        if (!_exists(id)) return;
        if (settlement.tasks(id).status != Settlement.Status.Matched) return;

        address executor = settlement.tasks(id).executor;
        if (executor == address(0)) return;

        vm.prank(executor);
        settlement.submitResult(id);
        if (settlement.tasks(id).status != Settlement.Status.Submitted) {
            _record(this.opSubmit.selector);
        }
    }

    function opAttest(uint256 taskSeed, uint256 verifierSeed) external {
        if (taskIds.length == 0) return;
        bytes32 id = taskIds[taskSeed % taskIds.length];
        if (!_exists(id)) return;
        if (settlement.tasks(id).status != Settlement.Status.Submitted) return;

        address verifier = _pick(verifiers, verifierSeed);
        if (!settlement.isVerifier(verifier)) return;
        if (settlement.hasAttested(id, verifier)) return;

        vm.prank(verifier);
        settlement.attestVerified(id);
    }

    function opDispute(uint256 taskSeed, uint256 partySeed) external {
        if (taskIds.length == 0) return;
        bytes32 id = taskIds[taskSeed % taskIds.length];
        if (!_exists(id)) return;

        Settlement.Status status = settlement.tasks(id).status;
        if (status != Settlement.Status.Matched && status != Settlement.Status.Submitted) return;

        address requester = settlement.tasks(id).requester;
        address executor = settlement.tasks(id).executor;
        address party = (partySeed % 2 == 0) ? requester : executor;
        if (party == address(0)) return;

        vm.prank(party);
        settlement.disputeTask(id);
        if (settlement.tasks(id).status != Settlement.Status.Disputed) {
            _record(this.opDispute.selector);
        }
    }

    function opSettle(uint256 taskSeed) external {
        if (taskIds.length == 0) return;
        bytes32 id = taskIds[taskSeed % taskIds.length];
        if (!_exists(id)) return;
        if (settlement.tasks(id).status != Settlement.Status.Verified) return;

        vm.prank(ownerAddr);
        settlement.settleTask(id);
        if (settlement.tasks(id).status != Settlement.Status.Settled) {
            _record(this.opSettle.selector);
        }
    }

    function opResolve(uint256 taskSeed, uint256 resolutionSeed) external {
        if (taskIds.length == 0) return;
        bytes32 id = taskIds[taskSeed % taskIds.length];
        if (!_exists(id)) return;
        if (settlement.tasks(id).status != Settlement.Status.Disputed) return;

        uint256 stake = settlement.tasks(id).stakeAmount;
        if (resolutionSeed % 3 == 2 && stake == 0) return; // slashing nothing is refused

        Settlement.DisputeResolution resolution =
            Settlement.DisputeResolution(resolutionSeed % 3);
        vm.prank(ownerAddr);
        settlement.resolveDispute(id, resolution);

        Settlement.Status expected = resolution == Settlement.DisputeResolution.PayExecutor
            ? Settlement.Status.Settled
            : (
                resolution == Settlement.DisputeResolution.RefundRequester
                    ? Settlement.Status.Refunded
                    : Settlement.Status.Slashed
            );
        if (settlement.tasks(id).status != expected) {
            _record(this.opResolve.selector);
        }
    }

    function opRefund(uint256 taskSeed) external {
        if (taskIds.length == 0) return;
        bytes32 id = taskIds[taskSeed % taskIds.length];
        if (!_exists(id)) return;

        Settlement.Status status = settlement.tasks(id).status;
        if (
            status != Settlement.Status.Open && status != Settlement.Status.Matched
                && status != Settlement.Status.Submitted && status != Settlement.Status.Verified
        ) {
            return;
        }

        address requester = settlement.tasks(id).requester;
        vm.prank(requester);
        settlement.refundTask(id);
        if (settlement.tasks(id).status != Settlement.Status.Refunded) {
            _record(this.opRefund.selector);
        }
    }

    function opWithdraw(uint256 accountSeed, uint256 amountSeed) external {
        address[] memory accounts = new address[](requesters.length + executors.length);
        uint256 n = 0;
        for (uint256 i = 0; i < requesters.length; ++i) {
            accounts[n++] = requesters[i];
        }
        for (uint256 i = 0; i < executors.length; ++i) {
            accounts[n++] = executors[i];
        }

        address account = accounts[accountSeed % n];
        uint256 available = settlement.credits(account);
        if (available == 0) return;

        // Half the time take everything, half the time take a slice: partial
        // withdrawals are the case where an off-by-one in the credit ledger would
        // hide behind a "withdraw all and end at zero" check.
        uint256 amount = (amountSeed % 2 == 0) ? available : 1 + (amountSeed % available);
        vm.prank(account);
        settlement.withdrawCredits(account, amount, "");
        if (settlement.credits(account) != available - amount) {
            _record(this.opWithdraw.selector);
        }
    }

    function opRoll(uint256 delta) external {
        vm.roll(block.number + 1 + (delta % 10));
    }
}

/// @notice Invariant and fuzz tests for the settlement balance invariant.
///
/// The invariant is: **the contract always holds at least every unwithdrawn
/// credit plus every live escrow.** Upstream had no such property at all — its
/// `totalStaked` was written and never read, and its unfunded `payable`
/// `createTask` made the property false by construction.
contract SettlementInvariantTest is Test {
    Settlement internal settlement;
    SettlementHandler internal handler;

    address internal ownerAddr = makeAddr("owner");
    address[] internal requesters;
    address[] internal executors;
    address[] internal verifiers;

    function setUp() public {
        requesters.push(makeAddr("requesterA"));
        requesters.push(makeAddr("requesterB"));
        executors.push(makeAddr("executorA"));
        executors.push(makeAddr("executorB"));
        executors.push(makeAddr("executorC"));
        verifiers.push(makeAddr("verifier1"));
        verifiers.push(makeAddr("verifier2"));
        verifiers.push(makeAddr("verifier3"));

        settlement = new Settlement(ownerAddr, verifiers, 2, 16, 5e6);

        for (uint256 i = 0; i < requesters.length; ++i) {
            vm.deal(requesters[i], 1_000 ether);
        }
        for (uint256 i = 0; i < executors.length; ++i) {
            vm.deal(executors[i], 1_000 ether);
        }

        handler = new SettlementHandler(settlement, ownerAddr, requesters, executors, verifiers);
        vm.deal(address(handler), 1_000 ether);

        // Only the handler drives state; the invariant then observes it.
        targetContract(address(handler));
        excludeSender(address(handler));

        vm.roll(1_000);
    }

    /// @notice The required invariant.
    function invariant_settlementBalanceCoversObligations() public view {
        assertGe(
            address(settlement).balance,
            settlement.totalCreditsLocked() + settlement.lockedEscrow(),
            "balance must cover every credit plus every open escrow"
        );
        assertTrue(settlement.isSolvent());
    }

    /// @notice The accounting identities that make the balance invariant
    ///         meaningful rather than trivially true.
    function invariant_settlementLedgerIdentities() public view {
        // Escrow is only ever created by creation/acceptance and only ever
        // destroyed by settlement, refund or dispute resolution; it can never
        // float free of the balance.
        assertLe(
            settlement.lockedEscrow(),
            address(settlement).balance,
            "escrow can never exceed the balance"
        );
        assertLe(
            settlement.totalCreditsLocked(),
            address(settlement).balance,
            "credits can never exceed the balance"
        );
    }

    /// @notice Consecutive-handler-call summary, printed so a failing run can be
    ///         replayed from the sequence that produced it.
    function invariant_callSummary() public view {
        handler.requestersLength();
        handler.executorsLength();
        handler.verifiersLength();
    }

    /// @notice If the balance invariant ever breaks, the handler's `violation`
    ///         slot names the operation that broke it.
    function invariant_noHandlerViolation() public view {
        assertEq(handler.violation(), bytes4(0), "a guarded handler call failed unexpectedly");
    }
}
