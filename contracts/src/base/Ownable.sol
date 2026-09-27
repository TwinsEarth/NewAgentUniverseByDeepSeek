// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title Ownable — two-step ownership transfer
/// @notice Minimal, dependency-free ownership base.
///
/// WHY THIS FILE EXISTS INSTEAD OF OPENZEPPELIN
/// --------------------------------------------
/// Upstream v2.5.6 shipped four `.sol` files with no compiler config, no tests
/// and no vendored dependencies; `onlyOwner` was declared in
/// `GovernanceToken.sol` and then never applied to anything. This rewrite needs
/// a dozen lines of ownership logic, so it is implemented here rather than
/// pulling in `@openzeppelin/contracts` (which would add a remapping and a
/// network fetch to every clean build). The only external dependency of this
/// tree is `forge-std`, and that is used solely by `test/` and `script/`.
///
/// // upstream v2.5.6 fix: ownership is a two-step handshake. Upstream had no
/// // ownership transfer at all (its `owner` was written once in the
/// // constructor), so a lost key meant a dead contract and a wrong owner could
/// // never be corrected. `transferOwnership` only *proposes*; the nominee must
/// // call `acceptOwnership`, so a typo in the new owner address cannot brick
/// // the admin surface.
contract Ownable {
    /// @notice Current owner. `address(0)` means the contract is renounced.
    address public owner;
    /// @notice Address nominated by `transferOwnership` and not yet accepted.
    address public pendingOwner;

    /// @notice Emitted when a new owner is proposed (step 1).
    event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner);
    /// @notice Emitted when a proposed owner accepts (step 2).
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    error NotOwner(address caller);
    error ZeroAddress();
    error NotPendingOwner(address caller);

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner(msg.sender);
        _;
    }

    /// @param initialOwner Receives ownership immediately. Must not be zero:
    ///        deploying with `address(0)` would produce a contract with no admin
    ///        at all, which is indistinguishable from a permanently broken one.
    constructor(address initialOwner) {
        if (initialOwner == address(0)) revert ZeroAddress();
        owner = initialOwner;
        emit OwnershipTransferred(address(0), initialOwner);
    }

    /// @notice Step 1: nominate `newOwner`. No authority moves yet.
    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert ZeroAddress();
        pendingOwner = newOwner;
        emit OwnershipTransferStarted(owner, newOwner);
    }

    /// @notice Step 2: the nominee claims ownership.
    function acceptOwnership() external {
        if (msg.sender != pendingOwner) revert NotPendingOwner(msg.sender);
        address previous = owner;
        owner = msg.sender;
        pendingOwner = address(0);
        emit OwnershipTransferred(previous, msg.sender);
    }

    /// @notice Step 1 of renouncing: also a handshake, so an accidental call
    ///         cannot leave a contract permanently unadministered in one click.
    function renounceOwnership() external onlyOwner {
        pendingOwner = address(0);
        emit OwnershipTransferStarted(owner, address(0));
    }
}
