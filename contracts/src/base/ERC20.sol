// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title ERC20 — minimal, self-contained ERC-20 with a checkpoint hook
/// @notice Dependency-free ERC-20 used by `GovernanceToken`.
///
/// WHY THIS FILE EXISTS INSTEAD OF OPENZEPPELIN
/// --------------------------------------------
/// The on-chain token needs exactly three things: balances, an allowance
/// surface, and a single internal hook that fires after every balance mutation
/// so that `GovernanceToken` can move voting power. Vendoring ~150 lines keeps
/// the build reproducible with nothing but `forge-std`; see `contracts/README.md`.
///
/// DECIMALS
/// --------
/// `decimals()` is **6**, matching `crates/nau-core/src/domain/money.rs`
/// (`DECIMALS = 6`, `MINOR_UNITS_PER_MAJOR = 1_000_000`). One whole NAU token is
/// 1_000_000 base units, which is exactly one `Money` minor unit. Every amount
/// crossing this boundary is therefore an integer count of minor units, never a
/// float — the canonical-payload rules in `conformance/vectors.json` reject
/// floats precisely so that 100, 100.0 and 1e2 cannot disagree across languages.
abstract contract ERC20 {
    string public name;
    string public symbol;
    uint8 public constant decimals = 6;

    uint256 public totalSupply;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    error ZeroAddress();
    error ZeroAmount();
    error InsufficientBalance(address account, uint256 available, uint256 required);
    error InsufficientAllowance(address spender, uint256 available, uint256 required);

    constructor(string memory name_, string memory symbol_) {
        name = name_;
        symbol = symbol_;
    }

    /// @notice Move `amount` from the caller to `to`.
    function transfer(address to, uint256 amount) external returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }

    /// @notice Approve `spender` to move `amount` of the caller's balance.
    ///
    /// NOTE: unlike some ERC-20 implementations this does **not** require a
    /// zero-first reset, so the classic approve-race exists. It is documented
    /// rather than papered over: integrators should set the allowance to zero
    /// before changing it, or use `increaseAllowance`.
    function approve(address spender, uint256 amount) external returns (bool) {
        _approve(msg.sender, spender, amount);
        return true;
    }

    /// @notice Atomically raise the caller's allowance for `spender`.
    function increaseAllowance(address spender, uint256 added) external returns (bool) {
        uint256 current = allowance[msg.sender][spender];
        _approve(msg.sender, spender, current + added);
        return true;
    }

    /// @notice Move `amount` from `from` to `to` using the caller's allowance.
    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        if (allowed != type(uint256).max) {
            if (allowed < amount) revert InsufficientAllowance(msg.sender, allowed, amount);
            unchecked {
                _approve(from, msg.sender, allowed - amount);
            }
        }
        _transfer(from, to, amount);
        return true;
    }

    function _transfer(address from, address to, uint256 amount) internal {
        if (from == address(0) || to == address(0)) revert ZeroAddress();
        _update(from, to, amount);
    }

    function _approve(address owner_, address spender, uint256 amount) internal {
        if (owner_ == address(0) || spender == address(0)) revert ZeroAddress();
        allowance[owner_][spender] = amount;
        emit Approval(owner_, spender, amount);
    }

    /// @dev The single mutation point. `from == address(0)` mints, `to ==
    ///      address(0)` burns, otherwise it is a transfer. Keeping every balance
    ///      change here is what lets `GovernanceToken` hook vote movement in one
    ///      place instead of in each of transfer/transferFrom/mint/burn.
    function _update(address from, address to, uint256 amount) internal virtual {
        if (amount == 0) revert ZeroAmount();

        if (from == address(0)) {
            totalSupply += amount;
        } else {
            uint256 fromBalance = balanceOf[from];
            if (fromBalance < amount) revert InsufficientBalance(from, fromBalance, amount);
            unchecked {
                balanceOf[from] = fromBalance - amount;
            }
        }

        if (to == address(0)) {
            totalSupply -= amount;
        } else {
            balanceOf[to] += amount;
        }

        emit Transfer(from, to, amount);
    }
}
