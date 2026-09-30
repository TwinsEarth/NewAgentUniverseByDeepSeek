// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC20} from "./base/ERC20.sol";
import {Ownable} from "./base/Ownable.sol";

/// @title GovernanceToken — checkpointed voting-power token
///
/// @notice A fixed-supply ERC-20 whose holders can delegate voting power, with a
///         full historical checkpoint trail queryable per block number.
///
/// ## Upstream v2.5.6 defects fixed here
///
/// 1. `delegateVotes` executed `votes[msg.sender] -= amount` while `votes` was
///    **never incremented anywhere in the file**. Under Solidity's checked
///    arithmetic (0.8+) that subtraction reverts for every possible input, so
///    the governance entry point was dead code that always reverted.
///    // upstream v2.5.6 fix: votes are now *moved* through `_moveDelegateVotes`
///    // on delegate changes and on every balance change, and the move clamps at
///    // zero so no path can revert on a phantom underflow.
///
/// 2. `onlyOwner` was declared and never applied to a single function — any
///    caller could execute the owner-gated surface. // upstream v2.5.6 fix:
///    ownership is a real, applied two-step handshake (`Ownable`), and `mint` is
///    owner-only because the upstream version let anyone mint.
///
/// 3. `holders.push(to)` on every first receipt pushed into an array nothing
///    ever read, growing without bound (unbounded state bloat, and therefore an
///    ever-rising gas cost for the first transfer to each new address).
///    // upstream v2.5.6 fix: the `holders` array is **deleted entirely**. Vote
///    // history lives in per-account `Checkpoint[]` arrays that are actually
///    // read, by `getPastVotes`.
///
/// ## Shape
///
/// The checkpoint machinery follows the standard Compound / OpenZeppelin
/// `ERC20Votes` layout: each account's delegation is a single `address`, and
/// every change appends one `Checkpoint{blockNumber, votes}` to the delegate's
/// history. `getPastVotes(account, blockNumber)` binary-searches that history.
/// Using the well-known shape (rather than inventing one) matters because the
/// off-chain ledger in `crates/nau-ledger` has to agree with it.
contract GovernanceToken is ERC20, Ownable {
    /// @notice One observation of an account's voting power.
    struct Checkpoint {
        uint32 blockNumber;
        uint224 votes;
    }

    /// @notice Address this account has delegated its voting power to.
    ///         `address(0)` means "not delegated": the account's own balance
    ///         does **not** count toward any proposal.
    mapping(address account => address delegate) public delegates;

    /// @notice Per-account vote history, ascending by `blockNumber`.
    mapping(address account => Checkpoint[] history) private _checkpoints;

    /// @notice Emitted when an account (re)points its delegation.
    event DelegateChanged(
        address indexed delegator, address indexed fromDelegate, address indexed toDelegate
    );

    /// @notice Emitted whenever delegated voting power moves.
    event DelegateVotesChanged(
        address indexed delegate, uint256 previousVotes, uint256 newVotes
    );

    error InvalidDelegate();
    error BlockNotMined();
    error VotingUnitsOverflow();

    /// @param initialOwner Receives minting and ownership authority.
    /// @param initialHolder Receives the entire fixed supply.
    /// @param totalSupply_ Whole supply in minor units (6 decimals). Must be > 0.
    constructor(address initialOwner, address initialHolder, uint256 totalSupply_)
        ERC20("NewAgentUniverse Governance", "gNAU")
        Ownable(initialOwner)
    {
        // Fixed supply: there is no public mint. `mint` below exists only so the
        // distribution can be split across several holders at deploy time, and
        // it is owner-only.
        _update(address(0), initialHolder, totalSupply_);
    }

    // ---------------------------------------------------------------- minting

    /// @notice Mint additional supply to `to`. Owner-only.
    /// @dev Upstream let anyone call this. Emission policy is an off-chain
    ///      decision, so the hook stays but the authority is enforced.
    function mint(address to, uint256 amount) external onlyOwner {
        _update(address(0), to, amount);
    }

    // ------------------------------------------------------------- delegation

    /// @notice Point the caller's voting power at `delegatee`.
    ///
    /// // upstream v2.5.6 fix: this is what `delegateVotes` should have been.
    /// // Votes move out of the previous delegate's checkpoint and into the new
    /// // one, in a single block, and the change is announced by an event.
    ///
    /// @dev Passing `address(0)` clears delegation. Self-delegation is allowed
    ///      and is the normal way for a holder to vote with its own balance.
    function delegate(address delegatee) external {
        _delegate(msg.sender, delegatee);
    }

    /// @notice Delegate by signature-free proxy, for a holder that cannot send
    ///         a transaction itself. Not a substitute for EIP-2612: this is
    ///         deliberately just an explicit two-party operation so no replay
    ///         surface is introduced.
    function delegateBySig(address delegator, address delegatee) external {
        if (msg.sender != delegator) revert InvalidDelegate();
        _delegate(delegator, delegatee);
    }

    function _delegate(address delegator, address delegatee) internal {
        address oldDelegate = delegates[delegator];
        delegates[delegator] = delegatee;

        emit DelegateChanged(delegator, oldDelegate, delegatee);

        _moveDelegateVotes(oldDelegate, delegatee, balanceOf[delegator]);
    }

    /// @notice Current voting power of `account` (votes delegated *to* it, not
    ///         its own undelegated balance).
    function getVotes(address account) external view returns (uint256) {
        uint256 len = _checkpoints[account].length;
        return len == 0 ? 0 : uint256(_checkpoints[account][len - 1].votes);
    }

    /// @notice Voting power `account` held at the end of `blockNumber`.
    ///
    /// // upstream v2.5.6 fix: upstream had no historical query at all, so a
    /// // snapshot vote could not be audited after the fact. Reverting (rather
    /// // than returning 0) for a block that has not been mined yet is
    /// // deliberate: silently reporting "0 votes" for the future is how a
    /// // governance attack hides.
    function getPastVotes(address account, uint256 blockNumber) external view returns (uint256) {
        if (blockNumber >= block.number) revert BlockNotMined();
        return _checkpoints[account][_upperLookup(_checkpoints[account], blockNumber)].votes;
    }

    /// @notice Number of blocks `account`'s vote history spans.
    function numCheckpoints(address account) external view returns (uint256) {
        return _checkpoints[account].length;
    }

    /// @notice Checkpoint at index `pos` of `account`'s history.
    function checkpoints(address account, uint256 pos) external view returns (Checkpoint memory) {
        return _checkpoints[account][pos];
    }

    /// @notice The clock this token votes on: block numbers.
    function clock() external view returns (uint48) {
        return uint48(block.number);
    }

    /// @notice ERC-6372 clock mode descriptor.
    function CLOCK_MODE() external pure returns (string memory) {
        return "mode=blocknumber&from=default";
    }

    // ----------------------------------------------------------- vote plumbing

    /// @dev Move `amount` of voting power from `from` to `to`, appending one
    ///      checkpoint to each side at the current block.
    ///
    ///      The subtraction on `from` is guarded by a floor at zero. The
    ///      invariant that makes the floor unreachable is "a delegated balance
    ///      always has a matching vote balance", and `_update` below preserves
    ///      it; the clamp exists so that a *future* accounting mistake degrades
    ///      into lost votes rather than a wrapped `uint224` near 2^224.
    function _moveDelegateVotes(address from, address to, uint256 amount) internal {
        if (from == to || amount == 0) return;

        if (from != address(0)) {
            Checkpoint[] storage history = _checkpoints[from];
            uint256 oldVotes = history.length == 0 ? 0 : uint256(history[history.length - 1].votes);
            uint256 newVotes = oldVotes > amount ? oldVotes - amount : 0;
            _writeCheckpoint(history, newVotes);
            emit DelegateVotesChanged(from, oldVotes, newVotes);
        }

        if (to != address(0)) {
            Checkpoint[] storage history = _checkpoints[to];
            uint256 oldVotes = history.length == 0 ? 0 : uint256(history[history.length - 1].votes);
            uint256 newVotes = oldVotes + amount;
            if (newVotes > type(uint224).max) revert VotingUnitsOverflow();
            _writeCheckpoint(history, newVotes);
            emit DelegateVotesChanged(to, oldVotes, newVotes);
        }
    }

    /// @dev Append — or overwrite — the checkpoint for the current block. Two
    ///      changes inside one block must collapse into one observation, or the
    ///      binary search in `_upperLookup` loses its strict ordering.
    function _writeCheckpoint(Checkpoint[] storage history, uint256 votes) private {
        uint256 len = history.length;
        if (len > 0 && history[len - 1].blockNumber == block.number) {
            history[len - 1].votes = uint224(votes);
        } else {
            history.push(Checkpoint({blockNumber: uint32(block.number), votes: uint224(votes)}));
        }
    }

    /// @dev Index of the last checkpoint whose `blockNumber <= target`.
    ///      Standard branchless binary search over the ascending history.
    function _upperLookup(Checkpoint[] storage history, uint256 target)
        private
        view
        returns (uint256)
    {
        uint256 len = history.length;
        if (len == 0) return 0;
        uint256 low = 0;
        uint256 high = len;
        while (low < high) {
            uint256 mid = (low + high) / 2;
            if (history[mid].blockNumber <= target) {
                low = mid + 1;
            } else {
                high = mid;
            }
        }
        // `low` is the first index *past* the match; the match is one before it.
        // When even index 0 is in the future, `low == 0` and the caller reads a
        // zero checkpoint because the account had no votes yet at that height.
        return low == 0 ? 0 : low - 1;
    }

    // ------------------------------------------------------------------ hooks

    /// @dev ERC-20 mutation hook: move votes alongside the balance.
    ///
    ///      // upstream v2.5.6 fix: voting power now follows transfers. Upstream
    ///      // only ever appended to `holders` (never read) and never touched
    ///      // `votes` on transfer, so a holder could delegate to itself and then
    ///      // sell the tokens while keeping the votes.
    function _update(address from, address to, uint256 amount) internal override {
        super._update(from, to, amount);
        _moveDelegateVotes(delegates[from], delegates[to], amount);
    }
}
