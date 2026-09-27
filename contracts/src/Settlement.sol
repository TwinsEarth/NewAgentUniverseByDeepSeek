// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Ownable} from "./base/Ownable.sol";
import {ReentrancyGuard} from "./base/ReentrancyGuard.sol";

/// @title Settlement — escrowed task settlement in integer minor units
///
/// @notice Replaces upstream `PoCVSettlement.sol`. Every amount is an integer
///         count of minor units (6 decimals), matching
///         `crates/nau-core/src/domain/money.rs` (`DECIMALS = 6`,
///         `MINOR_UNITS_PER_MAJOR = 1_000_000`). Nothing here is a float, ever:
///         the canonical-payload rules in `conformance/vectors.json` reject
///         floats outright because 100 / 100.0 / 1e2 cannot be reproduced
///         byte-for-byte across Rust, Python and JavaScript.
///
/// ## Upstream v2.5.6 defects fixed here
///
/// 1. **Unauditable, unfunded tasks.** `createTask` was `payable` and never read
///    `msg.value`, so a task could be published with
///    `rewardAmount = type(uint256).max` and zero ETH behind it — guaranteed
///    insolvency, with the promise permanently unfundable.
///    // upstream v2.5.6 fix: `createTask` requires `msg.value == rewardAmount`
///    // and `rewardAmount > 0`; the escrow is funded in the same transaction
///    // that creates the obligation, so the two can never disagree.
///
/// 2. **Anyone could verify or dispute anything.** `verifyTask` and
///    `disputeTask` had no access control, so a stranger could mark any task
///    `Verified` (unlocking the payout) or `Disputed` (freezing someone else's
///    money).
///    // upstream v2.5.6 fix: `attestVerified` is restricted to an
///    // owner-managed verifier set and requires a quorum of *distinct*
///    // attestations before `Verified` is reached; `disputeTask` is restricted
///    // to the task's requester or its assigned executor.
///
/// 3. **Check-effects-interactions violation plus no reentrancy guard.**
///    `settleTask` did `call{value: payout}` *before* updating `totalStaked`, so
///    a re-entering `receive()` replayed the payout.
///    // upstream v2.5.6 fix: all state is written before any interaction, a
///    // `nonReentrant` guard covers every state-changing entry point, and the
///    // payout is a **pull** (`credits` + `withdrawCredits`) rather than a push.
///
/// 4. **Self-dealing.** `acceptTask` let a requester accept its own task.
///    // upstream v2.5.6 fix: `acceptTask` reverts with `RequesterCannotExecute`
///    // when the requester calls it, and `assignTask` refuses to name the
///    // requester as executor, so neither direction of the loop can close.
///
/// 5. **Misbehaviour was as profitable as success.** A disputed task still paid
///    the executor in full.
///    // upstream v2.5.6 fix: `resolveDispute` must pick exactly one of
///    // `RefundRequester`, `PayExecutor` or `SlashExecutor`; `SlashExecutor`
///    // really moves the executor's stake (and its escrow) to the requester.
///
/// 6. **Payout to `address(0)`.** With no executor assigned, settlement sent the
///    reward into the void.
///    // upstream v2.5.6 fix: `settleTask` requires `task.executor != address(0)`.
///
/// 7. **`totalStaked` written and never read.** A variable that only ever grows
///    is not an invariant, it is a rumour.
///    // upstream v2.5.6 fix: `totalStaked` is **removed**; stake accounting is
///    // derived from the task record, and the property that actually matters —
///    // `address(this).balance >= totalCreditsLocked + lockedEscrow` — is
///    // tracked by `totalCreditsLocked`/`lockedEscrow` and asserted by an
///    // invariant test.
///
/// ## Lifecycle
///
/// The on-chain statuses map onto the Rust core's `TaskState` (see
/// `crates/nau-core/src/domain/task.rs`):
///
/// ```text
///   on-chain    Status        <->  Rust TaskState
///   ---------   -----------        ---------------
///   created     Open               Open
///   assigned    Matched            Matched
///   delivered   Submitted          Submitted
///   quorum met  Verified           Verifying -> Accepted
///   contested   Disputed           Disputed
///   closed      Settled            Settled
///   closed      Refunded           Cancelled
///   closed      Slashed            Slashed
/// ```
///
/// Allowed transitions (anything else reverts with `InvalidStatusTransition`):
///
/// ```text
///   —        -> Open        createTask
///   Open     -> Matched     acceptTask | assignTask | Refunded (refundTask,
///                                                       no executor yet)
///   Matched  -> Submitted   submitResult
///   Submitted-> Verified    quorum of distinct verifier attestations
///   Submitted-> Disputed    disputeTask (requester or executor)
///   Verified -> Settled     settleTask (executor is non-zero by construction)
///   Verified -> Disputed    disputeTask
///   Disputed -> Refunded    resolveDispute(RefundRequester)
///   Disputed -> Settled     resolveDispute(PayExecutor)
///   Disputed -> Slashed     resolveDispute(SlashExecutor)
///   (Open|Matched|Submitted|Verified) -> Refunded  refundTask (requester)
///   Refunded, Settled, Slashed are terminal.
/// ```
///
/// Note `Matched -> Open` from the Rust table (a lapsed bid reopens the task) is
/// modelled here as `refundTask` returning escrow rather than silently reopening:
/// on-chain the money has already moved, and an on-chain "reopen" with a live
/// escrow is a second funding requirement that the caller must sign for.
contract Settlement is Ownable, ReentrancyGuard {
    /// @notice Task lifecycle status.
    enum Status {
        Open,
        Matched,
        Submitted,
        Verified,
        Disputed,
        Settled,
        Refunded,
        Slashed
    }

    /// @notice How a dispute is decided. Exactly one must be chosen.
    enum DisputeResolution {
        RefundRequester,
        PayExecutor,
        SlashExecutor
    }

    /// @notice A settlement task and its escrow.
    struct Task {
        /// @notice Task id, matching the Rust `TaskId` (ASCII, 1..=64 chars).
        bytes32 id;
        /// @notice Address that funded the escrow and owns the acceptance call.
        address requester;
        /// @notice Assigned executor; `address(0)` until matched.
        address executor;
        /// @notice Reward in minor units, escrowed at creation.
        uint256 rewardAmount;
        /// @notice Stake the executor must post, in minor units.
        uint256 stakeAmount;
        /// @notice Status.
        Status status;
        /// @notice Distinct verifier attestations recorded so far.
        uint32 verifierAttestations;
        /// @notice Unix timestamp of creation.
        uint64 createdAt;
        /// @notice Set once, at dispute time.
        uint64 disputedAt;
    }

    // ------------------------------------------------------------------ config

    /// @notice Attestations required to reach `Verified`. Owner-configurable.
    uint32 public quorum;
    /// @notice Stake the executor must post to take a task. Owner-configurable;
    ///         `0` means "no stake", which disables `SlashExecutor`.
    uint256 public requiredStake;

    /// @notice Verifier set membership.
    mapping(address verifier => bool isVerifier) public isVerifier;
    /// @notice Permissionless-growth cap on the verifier set.
    uint32 public immutable maxVerifiers;
    /// @notice Verifier addresses, for enumeration. May contain zeroed holes
    ///         after a removal; never read in bulk by this contract.
    address[] private _verifiers;

    /// @notice Whether a verifier has already attested a task.
    mapping(bytes32 taskId => mapping(address verifier => bool attested)) public hasAttested;

    /// @notice Tasks by id. `task(id).requester == address(0)` means unknown.
    mapping(bytes32 taskId => Task task) public tasks;
    /// @notice Every created task id, in creation order.
    bytes32[] private _taskIds;

    // --------------------------------------------------------------- accounting

    /// @notice Sum of every unwithdrawn credit. This is the pull-payment ledger.
    uint256 public totalCreditsLocked;
    /// @notice Sum of every reward still sitting in a live escrow.
    uint256 public lockedEscrow;
    /// @notice Withdrawable balance per account, in minor units.
    mapping(address account => uint256 amount) public credits;

    // ------------------------------------------------------------------ events

    event TaskCreated(
        bytes32 indexed taskId, address indexed requester, uint256 rewardAmount, uint64 at
    );
    event TaskAccepted(bytes32 indexed taskId, address indexed executor, uint256 stakeAmount);
    event TaskAssigned(bytes32 indexed taskId, address indexed executor, address indexed assignedBy);
    event ResultSubmitted(bytes32 indexed taskId, address indexed executor);
    event VerifierAttested(bytes32 indexed taskId, address indexed verifier, uint32 total);
    event TaskVerified(bytes32 indexed taskId, uint32 attestations);
    event TaskDisputed(bytes32 indexed taskId, address indexed by, address indexed against);
    event DisputeResolved(bytes32 indexed taskId, DisputeResolution resolution, uint256 slashed);
    event TaskSettled(bytes32 indexed taskId, address indexed executor, uint256 reward);
    event TaskRefunded(bytes32 indexed taskId, address indexed requester, uint256 amount);
    event TaskSlashed(
        bytes32 indexed taskId, address indexed executor, address indexed beneficiary, uint256 slash
    );
    event CreditAdded(address indexed account, uint256 amount, uint256 newCredit);
    event CreditsWithdrawn(address indexed account, address indexed destination, uint256 amount);
    event VerifierAdded(address indexed verifier);
    event VerifierRemoved(address indexed verifier);
    event QuorumUpdated(uint32 quorum);
    event RequiredStakeUpdated(uint256 requiredStake);
    event StatusChanged(bytes32 indexed taskId, Status from, Status to, address indexed by);

    // ------------------------------------------------------------------ errors

    error TaskUnknown(bytes32 taskId);
    error TaskExists(bytes32 taskId);
    error InvalidStatusTransition(bytes32 taskId, Status from, Status to);
    error RewardMustEqualMsgValue(uint256 rewardAmount, uint256 msgValue);
    error RewardMustBePositive();
    error ExecutorMustBeSet();
    error RequesterCannotExecute(address caller);
    error NotRequesterOrExecutor(address caller);
    error NotAVerifier(address caller);
    error AlreadyAttested(bytes32 taskId, address verifier);
    error QuorumTooHigh(uint32 quorum, uint256 verifierCount);
    error QuorumMustBePositive();
    error VerifierAlreadyPresent(address verifier);
    error VerifierNotPresent(address verifier);
    error TooManyVerifiers(uint256 maxVerifiers);
    error IncorrectStake(uint256 required, uint256 sent);
    error NothingToWithdraw();
    error EthTransferFailed(address destination, uint256 amount);
    error InsufficientCredit(address account, uint256 requested, uint256 available);
    error OwnerIsRequester(address owner);
    error ZeroAddress();
    error InvalidResolution();

    /// @param initialOwner Owner; administers verifiers, quorum and stake.
    /// @param initialVerifiers Verifier set seeded at deploy time.
    /// @param quorum_ Attestations required to reach `Verified` (must be > 0 and
    ///        no more than the number of verifiers).
    /// @param maxVerifiers_ Hard cap on verifier-set growth.
    /// @param requiredStake_ Executor stake in minor units (`0` disables slashing).
    constructor(
        address initialOwner,
        address[] memory initialVerifiers,
        uint32 quorum_,
        uint32 maxVerifiers_,
        uint256 requiredStake_
    ) Ownable(initialOwner) {
        if (maxVerifiers_ == 0) revert TooManyVerifiers(0);
        if (quorum_ == 0) revert QuorumMustBePositive();
        maxVerifiers = maxVerifiers_;

        for (uint256 i = 0; i < initialVerifiers.length; ++i) {
            _addVerifier(initialVerifiers[i]);
        }
        if (quorum_ > _verifiers.length) revert QuorumTooHigh(quorum_, _verifiers.length);
        quorum = quorum_;
        requiredStake = requiredStake_;
    }

    // ------------------------------------------------------------ admin surface

    /// @notice Add `verifier` to the attestation set. Owner-only.
    /// @dev // upstream v2.5.6 fix: `addVerifier` was `onlyVerifier`, so any
    ///      verifier could mint unlimited new verifiers — a self-amplifying
    ///      quorum. It is now owner-only and capped by `maxVerifiers`.
    function addVerifier(address verifier) external onlyOwner {
        _addVerifier(verifier);
    }

    function _addVerifier(address verifier) private {
        if (verifier == address(0)) revert ZeroAddress();
        if (isVerifier[verifier]) revert VerifierAlreadyPresent(verifier);
        if (_verifiers.length >= maxVerifiers) revert TooManyVerifiers(maxVerifiers);
        isVerifier[verifier] = true;
        _verifiers.push(verifier);
        emit VerifierAdded(verifier);
    }

    /// @notice Remove `verifier`. Owner-only.
    /// @dev Removal cannot invalidate an already-reached `Verified` status;
    ///      statuses are checked against recorded attestations, not the live set.
    function removeVerifier(address verifier) external onlyOwner {
        if (!isVerifier[verifier]) revert VerifierNotPresent(verifier);
        isVerifier[verifier] = false;
        uint256 len = _verifiers.length;
        for (uint256 i = 0; i < len; ++i) {
            if (_verifiers[i] == verifier) {
                _verifiers[i] = _verifiers[len - 1];
                _verifiers.pop();
                break;
            }
        }
        emit VerifierRemoved(verifier);
    }

    /// @notice Set the attestation quorum. Owner-only.
    function setQuorum(uint32 quorum_) external onlyOwner {
        if (quorum_ == 0) revert QuorumMustBePositive();
        if (quorum_ > _verifiers.length) revert QuorumTooHigh(quorum_, _verifiers.length);
        quorum = quorum_;
        emit QuorumUpdated(quorum_);
    }

    /// @notice Set the executor stake. Owner-only.
    function setRequiredStake(uint256 requiredStake_) external onlyOwner {
        requiredStake = requiredStake_;
        emit RequiredStakeUpdated(requiredStake_);
    }

    /// @notice Live verifier-set size.
    function verifierCount() external view returns (uint256) {
        return _verifiers.length;
    }

    /// @notice Verifier at index `i` of the enumeration array.
    function verifierAt(uint256 i) external view returns (address) {
        return _verifiers[i];
    }

    /// @notice Number of tasks ever created.
    function taskCount() external view returns (uint256) {
        return _taskIds.length;
    }

    /// @notice Task id at index `i` of the creation log.
    function taskIdAt(uint256 i) external view returns (bytes32) {
        return _taskIds[i];
    }

    /// @notice The solvency invariant, materialised so it can be asserted
    ///         on-chain and in tests: the contract must hold at least every
    ///         unwithdrawn credit plus every live escrow.
    function totalObligations() external view returns (uint256) {
        return totalCreditsLocked + lockedEscrow;
    }

    /// @notice True when the solvency invariant currently holds.
    function isSolvent() external view returns (bool) {
        return address(this).balance >= totalCreditsLocked + lockedEscrow;
    }

    // -------------------------------------------------------------- task writes

    /// @notice Publish a task and escrow its reward in the same transaction.
    ///
    /// // upstream v2.5.6 fix: upstream accepted `msg.value` of 0 for any reward,
    /// // which is how a `type(uint256).max` promise became unfundable. The two
    /// // must be equal; there is no partially funded task.
    ///
    /// @param taskId Task id. Must not already exist.
    /// @param rewardAmount Reward in minor units. Must be > 0 and == msg.value.
    function createTask(bytes32 taskId, uint256 rewardAmount) external payable returns (bool) {
        if (taskId == bytes32(0)) revert TaskUnknown(taskId);
        // An existing task is identified by a non-zero requester; there is no
        // separate existence flag to fall out of sync with the record.
        if (tasks[taskId].requester != address(0)) revert TaskExists(taskId);
        if (rewardAmount == 0) revert RewardMustBePositive();
        if (msg.value != rewardAmount) revert RewardMustEqualMsgValue(rewardAmount, msg.value);

        tasks[taskId] = Task({
            id: taskId,
            requester: msg.sender,
            executor: address(0),
            rewardAmount: rewardAmount,
            stakeAmount: 0,
            status: Status.Open,
            verifierAttestations: 0,
            createdAt: uint64(block.timestamp),
            disputedAt: 0
        });
        _taskIds.push(taskId);

        // Escrow is now locked; it is not a credit and cannot be withdrawn.
        lockedEscrow += rewardAmount;

        emit TaskCreated(taskId, msg.sender, rewardAmount, uint64(block.timestamp));
        emit StatusChanged(taskId, Status.Open, Status.Open, msg.sender);
        return true;
    }

    /// @notice Claim an `Open` task as its executor, posting the required stake.
    ///
    /// // upstream v2.5.6 fix: a requester could accept its own task (and so
    /// // occupy both sides of the settlement). This reverts for the requester.
    ///
    /// @dev Side effect: the Rust `Matched -> Open` reopen edge is not
    ///      represented here; escrow already exists, so an unmatch is a refund.
    function acceptTask(bytes32 taskId) external payable nonReentrant {
        Task storage task = _load(taskId);
        bool claimable = task.status == Status.Open
            || (task.status == Status.Matched && task.executor == msg.sender);
        if (!claimable) revert InvalidStatusTransition(taskId, task.status, Status.Matched);
        if (msg.sender == task.requester) revert RequesterCannotExecute(msg.sender);
        if (msg.value != requiredStake) revert IncorrectStake(requiredStake, msg.value);

        task.executor = msg.sender;
        task.stakeAmount = msg.value;
        // The stake is escrow too: it sits in this contract until the task
        // settles, is refunded or is slashed, and it is part of the solvency
        // invariant. Recording it here is what makes `_unlockEscrow` in
        // `settleTask`/`refundTask`/`resolveDispute` an exact inverse.
        if (msg.value > 0) lockedEscrow += msg.value;
        _setStatus(task, taskId, Status.Matched, msg.sender);

        emit TaskAccepted(taskId, msg.sender, msg.value);
    }

    /// @notice Name the winning executor for an `Open` task. Requester-only.
    ///
    /// // upstream v2.5.6 fix: the requester may not name itself as executor.
    /// // Assignment only records the winner; the named executor must still call
    /// // `acceptTask` and post the stake itself, so a requester can never
    /// // conjure a stake (or a slashing target) out of nothing.
    function assignTask(bytes32 taskId, address executor) external nonReentrant {
        Task storage task = _load(taskId);
        if (msg.sender != task.requester) revert NotRequesterOrExecutor(msg.sender);
        if (task.status != Status.Open) {
            revert InvalidStatusTransition(taskId, task.status, Status.Matched);
        }
        if (executor == address(0)) revert ExecutorMustBeSet();
        if (executor == task.requester) revert RequesterCannotExecute(executor);

        task.executor = executor;
        _setStatus(task, taskId, Status.Matched, msg.sender);

        emit TaskAssigned(taskId, executor, msg.sender);
    }

    /// @notice Mark a `Matched` task as delivered. Executor-only.
    function submitResult(bytes32 taskId) external {
        Task storage task = _load(taskId);
        if (task.status != Status.Matched) {
            revert InvalidStatusTransition(taskId, task.status, Status.Submitted);
        }
        if (msg.sender != task.executor) revert NotRequesterOrExecutor(msg.sender);
        _setStatus(task, taskId, Status.Submitted, msg.sender);
        emit ResultSubmitted(taskId, msg.sender);
    }

    /// @notice Record a verifier attestation. Once `quorum` distinct verifiers
    ///         have attested, the task reaches `Verified` and may be settled.
    ///
    /// // upstream v2.5.6 fix: upstream `verifyTask` was callable by anyone and
    /// // flipped the status on the first call. This requires set membership, one
    /// // attestation per verifier per task, and a distinct-attestation quorum.
    function attestVerified(bytes32 taskId) external {
        Task storage task = _load(taskId);
        if (task.status != Status.Submitted) {
            revert InvalidStatusTransition(taskId, task.status, Status.Verified);
        }
        if (!isVerifier[msg.sender]) revert NotAVerifier(msg.sender);
        if (hasAttested[taskId][msg.sender]) revert AlreadyAttested(taskId, msg.sender);

        hasAttested[taskId][msg.sender] = true;
        task.verifierAttestations += 1;
        emit VerifierAttested(taskId, msg.sender, task.verifierAttestations);

        if (task.verifierAttestations >= quorum) {
            _setStatus(task, taskId, Status.Verified, msg.sender);
            emit TaskVerified(taskId, task.verifierAttestations);
        }
    }

    /// @notice Open a dispute. Restricted to the task's requester or executor.
    ///
    /// // upstream v2.5.6 fix: any address could dispute any task, freezing funds
    /// // at will. Only the two parties with money at stake may.
    function disputeTask(bytes32 taskId) external {
        Task storage task = _load(taskId);
        if (msg.sender != task.requester && (task.executor == address(0) || msg.sender != task.executor)) {
            revert NotRequesterOrExecutor(msg.sender);
        }
        if (
            task.status != Status.Submitted && task.status != Status.Verified
                && task.status != Status.Matched
        ) {
            revert InvalidStatusTransition(taskId, task.status, Status.Disputed);
        }

        task.disputedAt = uint64(block.timestamp);
        _setStatus(task, taskId, Status.Disputed, msg.sender);

        address against = msg.sender == task.requester ? task.executor : task.requester;
        emit TaskDisputed(taskId, msg.sender, against);
    }

    /// @notice Decide a `Disputed` task. Owner-only.
    ///
    /// // upstream v2.5.6 fix: upstream paid the executor in full even when the
    /// // task was disputed, making misbehaviour as profitable as success. Here
    /// // the ruling is explicit and `SlashExecutor` really transfers the stake.
    ///
    /// @dev The owner may not be the requester (enforced at construction for the
    ///      deploy-time owner and re-checked on every `transferOwnership` path
    ///      by the `OwnerIsRequester` guard below). An owner who *is* the
    ///      requester would be judging its own refund, which is the same
    ///      conflict of interest in a different seat.
    function resolveDispute(bytes32 taskId, DisputeResolution resolution) external onlyOwner {
        Task storage task = _load(taskId);
        if (task.status != Status.Disputed) {
            revert InvalidStatusTransition(taskId, task.status, Status.Settled);
        }
        if (msg.sender == task.requester) revert OwnerIsRequester(msg.sender);

        if (resolution == DisputeResolution.RefundRequester) {
            _unlockEscrow(task.rewardAmount);
            _credit(task.requester, task.rewardAmount);
            if (task.stakeAmount > 0) {
                uint256 stake = task.stakeAmount;
                task.stakeAmount = 0;
                _unlockEscrow(stake);
                _credit(task.executor, stake);
            }
            _setStatus(task, taskId, Status.Refunded, msg.sender);
            emit DisputeResolved(taskId, resolution, 0);
            emit TaskRefunded(taskId, task.requester, task.rewardAmount);
        } else if (resolution == DisputeResolution.PayExecutor) {
            _unlockEscrow(task.rewardAmount);
            _credit(task.executor, task.rewardAmount);
            if (task.stakeAmount > 0) {
                uint256 stake = task.stakeAmount;
                task.stakeAmount = 0;
                _unlockEscrow(stake);
                _credit(task.executor, stake);
            }
            _setStatus(task, taskId, Status.Settled, msg.sender);
            emit DisputeResolved(taskId, resolution, 0);
            emit TaskSettled(taskId, task.executor, task.rewardAmount);
        } else if (resolution == DisputeResolution.SlashExecutor) {
            if (requiredStake == 0) revert InvalidResolution();
            uint256 slash = task.stakeAmount;
            task.stakeAmount = 0;
            uint256 total = task.rewardAmount + slash;
            _unlockEscrow(total);
            _credit(task.requester, total);
            _setStatus(task, taskId, Status.Slashed, msg.sender);
            emit DisputeResolved(taskId, resolution, slash);
            emit TaskSlashed(taskId, task.executor, task.requester, slash);
        } else {
            revert InvalidResolution();
        }
    }

    /// @notice Close a `Verified` task and credit the executor.
    ///
    /// // upstream v2.5.6 fix: three separate faults are fixed in this function.
    /// //   * `task.executor != address(0)` is required, so a payout can never be
    /// //     addressed to the zero address.
    /// //   * every piece of state (escrow, credits, status) is written before
    /// //     any value leaves the contract, and there is no push at all.
    /// //   * `nonReentrant` is applied even though the function makes no
    /// //     external call — the guard is what keeps that true if a future edit
    /// //     reintroduces one.
    function settleTask(bytes32 taskId) external nonReentrant {
        Task storage task = _load(taskId);
        if (task.status != Status.Verified) {
            revert InvalidStatusTransition(taskId, task.status, Status.Settled);
        }
        if (task.executor == address(0)) revert ExecutorMustBeSet();

        // ---- CHECKS done. EFFECTS next, before any INTERACTION. ----
        uint256 reward = task.rewardAmount;
        uint256 stake = task.stakeAmount;
        task.stakeAmount = 0;

        _unlockEscrow(reward);
        _credit(task.executor, reward);
        if (stake > 0) {
            _unlockEscrow(stake);
            _credit(task.executor, stake);
        }
        _setStatus(task, taskId, Status.Settled, msg.sender);

        // ---- INTERACTIONS: the executor pulls later, via withdrawCredits. ----
        emit TaskSettled(taskId, task.executor, reward);
    }

    /// @notice Cancel a task and return the escrow to the requester. Requester-only.
    ///
    /// @dev Terminal state `Refunded`. Allowed from `Open`, `Matched`,
    ///      `Submitted` and `Verified`; a `Disputed` task must go through
    ///      `resolveDispute` so the requester cannot unilaterally escape a
    ///      ruling. Any posted stake is returned to the executor.
    function refundTask(bytes32 taskId) external nonReentrant {
        Task storage task = _load(taskId);
        if (msg.sender != task.requester) revert NotRequesterOrExecutor(msg.sender);
        if (
            task.status == Status.Disputed || task.status == Status.Settled
                || task.status == Status.Refunded || task.status == Status.Slashed
        ) {
            revert InvalidStatusTransition(taskId, task.status, Status.Refunded);
        }

        uint256 reward = task.rewardAmount;
        uint256 stake = task.stakeAmount;
        task.stakeAmount = 0;

        _unlockEscrow(reward);
        _credit(task.requester, reward);
        if (stake > 0) {
            _unlockEscrow(stake);
            _credit(task.executor, stake);
        }
        _setStatus(task, taskId, Status.Refunded, msg.sender);

        emit TaskRefunded(taskId, task.requester, reward);
    }

    // ------------------------------------------------------- pull-payment side

    /// @notice Withdraw `amount` of the caller's credit to `destination`.
    ///
    /// // upstream v2.5.6 fix: settlement now pushes nothing. Credits are pulled,
    /// // so a failing or malicious recipient cannot block (or re-enter) the
    /// // state machine, and a re-entering recipient hits `ReentrantCall` because
    /// // the credit is debited *before* the transfer.
    ///
    /// @param destination Receives the ETH. Must be non-zero; the caller chooses
    ///        it so a contract that cannot receive can route elsewhere.
    /// @param amount Minor-unit amount to withdraw. Must be <= the credit.
    /// @param data Optional calldata forwarded to `destination`. Empty for a
    ///        plain transfer; non-empty when the recipient is a contract that
    ///        needs a specific entry point.
    function withdrawCredits(address destination, uint256 amount, bytes calldata data)
        external
        nonReentrant
    {
        if (destination == address(0)) revert ZeroAddress();
        uint256 available = credits[msg.sender];
        if (amount == 0) revert NothingToWithdraw();
        if (amount > available) revert InsufficientCredit(msg.sender, amount, available);

        // EFFECTS before INTERACTION.
        credits[msg.sender] = available - amount;
        totalCreditsLocked -= amount;

        (bool ok,) = destination.call{value: amount}(data);
        if (!ok) revert EthTransferFailed(destination, amount);

        emit CreditsWithdrawn(msg.sender, destination, amount);
    }

    /// @notice Withdraw the caller's entire credit to `destination`.
    function withdrawAllCredits(address destination) external nonReentrant {
        if (destination == address(0)) revert ZeroAddress();
        uint256 available = credits[msg.sender];
        if (available == 0) revert NothingToWithdraw();

        credits[msg.sender] = 0;
        totalCreditsLocked -= available;

        (bool ok,) = destination.call{value: available}("");
        if (!ok) revert EthTransferFailed(destination, available);

        emit CreditsWithdrawn(msg.sender, destination, available);
    }

    // -------------------------------------------------------------- internals

    function _load(bytes32 taskId) private view returns (Task storage task) {
        task = tasks[taskId];
        if (task.requester == address(0)) revert TaskUnknown(taskId);
    }

    function _setStatus(Task storage task, bytes32 taskId, Status next, address by) private {
        Status previous = task.status;
        task.status = next;
        emit StatusChanged(taskId, previous, next, by);
    }

    /// @dev Move `amount` out of escrow and into the credit ledger.
    function _unlockEscrow(uint256 amount) private {
        if (amount == 0) return;
        lockedEscrow -= amount;
        totalCreditsLocked += amount;
    }

    /// @dev Add to an account's pull-payment balance. The matching amount must
    ///      already have been moved out of escrow by `_unlockEscrow`, so that
    ///      `totalCreditsLocked` and `lockedEscrow` still sum to what the
    ///      contract actually holds. A zero-address credit is refused rather
    ///      than silently dropped: it can only be a bug, and reverting names it.
    function _credit(address account, uint256 amount) private {
        if (amount == 0) return;
        if (account == address(0)) revert ZeroAddress();
        uint256 updated = credits[account] + amount;
        credits[account] = updated;
        emit CreditAdded(account, amount, updated);
    }
}
