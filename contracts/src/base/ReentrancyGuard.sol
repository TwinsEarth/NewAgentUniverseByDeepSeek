// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title ReentrancyGuard — single-slot reentrancy lock
/// @notice Minimal, dependency-free reentrancy guard.
///
/// // upstream v2.5.6 fix: upstream `PoCVSettlement.sol` had NO reentrancy
/// // guard at all, and its `settleTask` performed `call{value: payout}` *before*
/// // touching `totalStaked`. A payout to a contract whose `receive()` re-entered
/// // `settleTask` therefore re-ran the payout from a state that still believed
/// // the task was unsettled: the same reward could be drained repeatedly. This
/// // guard closes the whole class of bug, including the nested-call variants
/// // that a naive `require(!locked)` written inside only one function misses.
///
/// The lock is set for the duration of the guarded function and released
/// afterwards. `nonReentrant` may be stacked on a function that another guarded
/// function calls *internally* — but never by re-entering the same call frame,
/// which is exactly what an attacker's `receive()` would be doing.
abstract contract ReentrancyGuard {
    uint256 private constant _UNLOCKED = 1;
    uint256 private constant _LOCKED = 2;

    uint256 private _reentrancyStatus = _UNLOCKED;

    /// @notice Thrown when a guarded function is entered while already running.
    error ReentrantCall();

    modifier nonReentrant() {
        if (_reentrancyStatus == _LOCKED) revert ReentrantCall();
        _reentrancyStatus = _LOCKED;
        _;
        _reentrancyStatus = _UNLOCKED;
    }
}
