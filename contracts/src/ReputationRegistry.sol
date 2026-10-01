// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Ownable} from "./base/Ownable.sol";

/// @title ReputationRegistry — bounded, epoch-keyed agent reputation
///
/// @notice Replaces upstream `ReputationBridge.sol`.
///
/// ## Upstream v2.5.6 defects fixed here
///
/// 1. `addVerifier` was `onlyVerifier`: **any** verifier could mint unlimited new
///    verifiers, and none could ever be removed or capped. A single compromised
///    (or simply hostile) verifier could take over the reporting set outright.
///    // upstream v2.5.6 fix: `addVerifier`/`removeVerifier` are owner-only, the
///    // set is bounded by a constructor-set `maxVerifiers`, and ownership moves
///    // through a two-step handshake.
///
/// 2. There was no owner at all — no recovery path and no accountable party.
///    // upstream v2.5.6 fix: `Ownable` with `transferOwnership` +
///    // `acceptOwnership`.
///
/// 3. Reputation was an arbitrary `uint32` with no bounds, while the off-chain
///    model in `crates/` scores in **basis points (0–10000)**. A value of
///    `4_000_000_000` was accepted and then dominated any comparison.
///    // upstream v2.5.6 fix: every dimension is normalised and then required to
///    // be <= `BPS_DENOMINATOR` (10_000), reverting with `ScoreAboveBps` if not.
///
/// 4. `snapshots[agent].push(...)` had no bound — one report per call, forever.
///    // upstream v2.5.6 fix: **one snapshot per agent per epoch**, idempotent by
///    // epoch and reverting with `EpochAlreadyRecorded` on a duplicate. The
///    // per-agent history is therefore bounded by the number of distinct epochs,
///    // and the current values are readable in O(1) via `latestEpoch`.
///
/// 5. The event emitted only 1 of the 4 dimensions, so three quarters of a
///    reputation report was invisible off-chain.
///    // upstream v2.5.6 fix: `ReputationRecorded` carries all four dimensions
///    // plus the epoch, the agent and the reporting verifier.
///
/// 6. `getLatestReputation` reverted for an unknown agent, forcing every caller
///    to special-case a fresh identity. // upstream v2.5.6 fix: it returns a
///    **zero-valued struct** and never reverts.
contract ReputationRegistry is Ownable {
    /// @notice 100% expressed in basis points. Every dimension is bounded by it.
    uint16 public constant BPS_DENOMINATOR = 10_000;

    /// @notice The four reputation dimensions, each in basis points (0..10000).
    struct Reputation {
        /// @notice Output quality as judged by the verifier.
        uint16 quality;
        /// @notice Whether the agent delivers when it says it will.
        uint16 reliability;
        /// @notice Latency relative to the promised ETA.
        uint16 speed;
        /// @notice Value delivered per unit of reward.
        uint16 costEfficiency;
    }

    /// @notice One immutable observation, keyed by epoch.
    struct Snapshot {
        /// @notice Epoch this report belongs to. Monotonic per agent.
        uint64 epoch;
        /// @notice When the report was written.
        uint64 recordedAt;
        /// @notice Address that reported it.
        address verifier;
        /// @notice The four dimensions.
        Reputation reputation;
    }

    /// @notice Permissionless-growth cap on the reporting set.
    uint32 public immutable maxVerifiers;

    /// @notice Reporting-set membership.
    mapping(address verifier => bool isVerifier) public isVerifier;
    /// @notice Reporting-set enumeration.
    address[] private _verifiers;

    /// @notice Per-agent snapshot history, ascending by epoch.
    mapping(address agent => Snapshot[] history) private _snapshots;
    /// @notice Highest epoch recorded for an agent.
    mapping(address agent => uint64 epoch) public latestEpoch;
    /// @notice Cached latest values, so `getLatestReputation` is O(1).
    mapping(address agent => Reputation reputation) private _latest;

    event VerifierAdded(address indexed verifier);
    event VerifierRemoved(address indexed verifier);
    event ReputationRecorded(
        address indexed agent,
        uint64 indexed epoch,
        address indexed verifier,
        uint16 quality,
        uint16 reliability,
        uint16 speed,
        uint16 costEfficiency
    );

    error NotAVerifier(address caller);
    error VerifierAlreadyPresent(address verifier);
    error VerifierNotPresent(address verifier);
    error TooManyVerifiers(uint256 maxVerifiers);
    error EpochAlreadyRecorded(address agent, uint64 epoch);
    error EpochNotIncreasing(uint64 previous, uint64 provided);
    error ScoreAboveBps(uint16 provided, uint16 max);

    /// @param initialOwner Owner; administers the reporting set. Consumed by the
    ///        `Ownable` two-step transfer.
    /// @param initialVerifiers Reporting set seeded at deploy time.
    /// @param maxVerifiers_ Hard cap on set growth. Must be > 0.
    constructor(address initialOwner, address[] memory initialVerifiers, uint32 maxVerifiers_)
        Ownable(initialOwner)
    {
        if (maxVerifiers_ == 0) revert TooManyVerifiers(0);
        maxVerifiers = maxVerifiers_;
        for (uint256 i = 0; i < initialVerifiers.length; ++i) {
            _addVerifier(initialVerifiers[i]);
        }
    }

    // ------------------------------------------------------------ admin surface

    /// @notice Add `verifier` to the reporting set. Owner-only.
    /// @dev // upstream v2.5.6 fix: was `onlyVerifier`, i.e. self-amplifying.
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

    /// @notice Remove `verifier` from the reporting set. Owner-only.
    /// @dev Already-written snapshots keep naming the verifier that wrote them;
    ///      removal changes who may write in future, it does not rewrite history.
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

    /// @notice Live reporting-set size.
    function verifierCount() external view returns (uint256) {
        return _verifiers.length;
    }

    /// @notice Reporting-set member at enumeration index `i`.
    function verifierAt(uint256 i) external view returns (address) {
        return _verifiers[i];
    }

    // ------------------------------------------------------------------ writes

    /// @notice Record one epoch's reputation for `agent`. Verifier-only.
    ///
    /// // upstream v2.5.6 fix: unbounded `push` replaced by one snapshot per
    /// // (agent, epoch); a duplicate epoch reverts instead of appending a second
    /// // row that off-chain readers would have to de-duplicate themselves.
    ///
    /// @param agent Agent whose reputation is being reported. Must be non-zero.
    /// @param epoch Epoch number. Must be strictly greater than the previous one
    ///        for this agent, so the history stays ordered and the accessor is
    ///        meaningful.
    /// @param r The four dimensions, each within 0..10000 basis points.
    function recordReputation(address agent, uint64 epoch, Reputation calldata r) external {
        if (!isVerifier[msg.sender]) revert NotAVerifier(msg.sender);
        if (agent == address(0)) revert ZeroAddress();

        Snapshot[] storage history = _snapshots[agent];
        if (history.length > 0) {
            uint64 previous = history[history.length - 1].epoch;
            if (epoch == previous) revert EpochAlreadyRecorded(agent, epoch);
            if (epoch < previous) revert EpochNotIncreasing(previous, epoch);
        }

        Reputation memory bounded = _bounded(r);

        history.push(
            Snapshot({
                epoch: epoch,
                recordedAt: uint64(block.timestamp),
                verifier: msg.sender,
                reputation: bounded
            })
        );
        latestEpoch[agent] = epoch;
        _latest[agent] = bounded;

        // All four dimensions, plus epoch and reporter: the upstream event
        // carried one dimension and no way to tell which report superseded it.
        emit ReputationRecorded(
            agent,
            epoch,
            msg.sender,
            bounded.quality,
            bounded.reliability,
            bounded.speed,
            bounded.costEfficiency
        );
    }

    // ------------------------------------------------------------------- reads

    /// @notice Latest recorded reputation for `agent`.
    /// @dev // upstream v2.5.6 fix: returns a zero-valued struct for an unknown
    ///      agent (all four dimensions 0) instead of reverting, so a caller
    ///      never has to special-case a fresh identity. Use `hasReputation` when
    ///      "no data" must be distinguished from "reported as all zeros".
    function getLatestReputation(address agent) external view returns (Reputation memory) {
        return _latest[agent];
    }

    /// @notice Whether `agent` has ever been reported on.
    function hasReputation(address agent) external view returns (bool) {
        return _snapshots[agent].length > 0;
    }

    /// @notice Number of snapshots recorded for `agent` (one per epoch).
    function snapshotCount(address agent) external view returns (uint256) {
        return _snapshots[agent].length;
    }

    /// @notice Snapshot at index `index` of `agent`'s ordered history.
    function snapshotAt(address agent, uint256 index) external view returns (Snapshot memory) {
        return _snapshots[agent][index];
    }

    /// @notice Snapshot recorded for `agent` at exactly `epoch`.
    /// @dev Reverts with `EpochAlreadyRecorded`-symmetric semantics are avoided
    ///      here: an unknown epoch returns `found = false` with a zero struct,
    ///      which is the non-reverting form. `latestEpoch` is the O(1) fast path
    ///      for the common case.
    function snapshotByEpoch(address agent, uint64 epoch)
        external
        view
        returns (bool found, Snapshot memory snapshot_)
    {
        Snapshot[] storage history = _snapshots[agent];
        for (uint256 i = 0; i < history.length; ++i) {
            if (history[i].epoch == epoch) {
                return (true, history[i]);
            }
        }
        return (false, snapshot_);
    }

    // --------------------------------------------------------------- internals

    /// @dev Bound each of the four dimensions, reverting on any that is out of
    ///      range. All four are checked, not just the first: one unbounded
    ///      dimension is enough to dominate every off-chain comparison.
    function _bounded(Reputation calldata r) private pure returns (Reputation memory) {
        return Reputation({
            quality: _bps(r.quality),
            reliability: _bps(r.reliability),
            speed: _bps(r.speed),
            costEfficiency: _bps(r.costEfficiency)
        });
    }

    /// @dev Bound one dimension to `BPS_DENOMINATOR`, reverting otherwise.
    ///
    ///      // upstream v2.5.6 fix: the upstream model took any `uint32` and
    ///      // compared it against 0..10000-based scores, so a report of
    ///      // 4_000_000_000 dominated every comparison for the rest of time.
    ///
    ///      The rule is deliberately absolute rather than "helpfully scaled":
    ///      the contract's unit is basis points, full stop. There is no
    ///      auto-detection of a caller that meant to send a 1e18-scaled
    ///      fraction, because auto-detection is exactly how `65_535` — a real
    ///      upstream-accepted value — would get silently reinterpreted instead
    ///      of rejected. Callers holding a fraction divide by `1e14` themselves;
    ///      that keeps the unit unambiguous in both directions.
    function _bps(uint16 value) private pure returns (uint16) {
        if (value > BPS_DENOMINATOR) revert ScoreAboveBps(value, BPS_DENOMINATOR);
        return value;
    }
}
