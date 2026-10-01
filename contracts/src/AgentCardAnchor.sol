// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title AgentCardAnchor — write-once, content-addressed agent-card anchors
///
/// @notice Anchors an agent card by digest and binds it permanently to the agent
///         DID hash that owns it and to the address that wrote it.
///
/// ## Upstream v2.5.6 defects fixed here
///
/// 1. `anchor()` was **unauthenticated and overwrote unconditionally**:
///    `anchors[cidHash] = Anchor(msg.sender, block.timestamp)`. Anybody could
///    re-anchor any existing `cidHash`, take over `anchors[cidHash].anchorer`,
///    and thereby impersonate the agent that really published that card.
///    // upstream v2.5.6 fix: anchoring is **first-write-wins and permanent**.
///    // A `cidHash` can be written exactly once; a second write reverts with
///    // `AlreadyAnchored`. There is no admin override, no expiry and no
///    // replace path, so "the anchorer of X" is a settled historical fact.
///
/// 2. `verify(cidHash)` returned `anchors[cidHash].anchoredAt > 0` — which is
///    true for *any* anchor, including one planted by an attacker, and proves
///    nothing about who the card belongs to.
///    // upstream v2.5.6 fix: `verify(bytes32 cidHash, bytes32 agentDidHash)`
///    // checks **both** the digest and the DID hash, so a valid card from agent A
///    // cannot be presented as evidence for agent B.
///
/// 3. `agentAnchors[msg.sender].push(...)` grew without bound.
///    // upstream v2.5.6 fix: a constructor-set `maxAnchorsPerAgent` cap makes
///    // the array's worst case a constant, and `anchorsOf` pages over it so
///    // callers never load an unbounded array into memory.
///
/// ## Why first-write-wins instead of an EIP-712 signature
///
/// The brief allowed either. First-write-wins was chosen because it is strictly
/// stronger here, and cheaper:
///
/// * Enforcement is a single mapping slot read. An EIP-712 path needs a nonce
///   per agent, a domain separator with a chain-id, and a signature-verification
///   surface (ECDSA malleability, `s` range, `v` values, `ecrecover` returning
///   `address(0)`) — three separate ways to get it wrong, per the "three of four
///   were not deployable" upstream baseline.
/// * A signature only proves *who signed*. It does not decide what happens when
///   two parties both hold valid signatures for the same `cidHash` — the exact
///   race the upstream overwrite bug created. Immutability decides it: the
///   earlier transaction wins and the later one reverts, deterministically.
/// * The card digest is a content hash. If an agent must publish a *revised*
///   card, the content differs, so the digest differs, and it is simply a new
///   anchor. There is nothing to overwrite.
///
/// The residual cost is that an agent who anchors the wrong digest cannot fix
/// it in place. That is accepted deliberately, and is why `anchorer` — not just
/// the DID hash — is stored and reported: a mistake is visible and attributable
/// rather than silently correctable by whoever gets there first.
///
/// ## Design choices that were "pick one and document it"
///
/// * `getAnchor` **reverts** for an unknown hash (`UnknownAnchor`) rather than
///   returning a zero struct. A zero struct is indistinguishable from a valid
///   anchor whose fields happen to be zero, and callers that forget to check
///   would treat it as proof of existence. `tryGetAnchor` is provided for
///   callers that genuinely want the non-reverting form.
/// * `agentDidHash` must be non-zero. `bytes32(0)` is reserved to mean "unset",
///   and allowing it would let a card be anchored with no agent binding at all —
///   which is the upstream `verify` bug in a new coat.
contract AgentCardAnchor {
    /// @notice A permanent, immutable anchor record.
    struct Anchor {
        /// @notice Address that submitted the first (and only) anchor.
        address anchorer;
        /// @notice Hash of the agent DID that owns the card, as supplied at
        ///         anchor time.
        bytes32 agentDidHash;
        /// @notice Block the anchor was written in.
        uint64 anchoredAtBlock;
        /// @notice Timestamp the anchor was written at.
        uint64 anchoredAtTime;
    }

    /// @notice Maximum anchors one address may ever create. Set in the
    ///         constructor so an operator can size it to the fleet.
    uint256 public immutable maxAnchorsPerAgent;

    /// @notice Number of anchors each address has created.
    mapping(address agent => uint256 count) public anchorCount;

    /// @notice Immutable anchor per card digest. Written once, never rewritten.
    mapping(bytes32 cidHash => Anchor anchor) private _anchors;

    /// @notice Anchors created by each address, capped at `maxAnchorsPerAgent`.
    mapping(address agent => bytes32[] cidHashes) private _agentAnchors;

    /// @notice Emitted exactly once per `cidHash`, for the rest of time.
    event Anchored(
        bytes32 indexed cidHash,
        bytes32 indexed agentDidHash,
        address indexed anchorer,
        uint256 anchoredAtBlock
    );

    error ZeroCidHash();
    error ZeroAgentDidHash();
    error AlreadyAnchored(bytes32 cidHash, address existingAnchorer);
    error AnchorLimitReached(address agent, uint256 maxAnchors);
    error UnknownAnchor(bytes32 cidHash);
    error PageOutOfRange(uint256 offset, uint256 limit, uint256 total);

    /// @param maxAnchorsPerAgent_ Cap on anchors per address. Must be > 0, or no
    ///        agent could ever anchor anything.
    constructor(uint256 maxAnchorsPerAgent_) {
        require(maxAnchorsPerAgent_ > 0, "maxAnchorsPerAgent must be > 0");
        maxAnchorsPerAgent = maxAnchorsPerAgent_;
    }

    // ------------------------------------------------------------------ writes

    /// @notice Anchor `cidHash` to `agentDidHash`, permanently.
    /// @dev First write wins. There is no second write and no administrative
    ///      override; see the contract-level note.
    /// @param cidHash Digest of the canonical agent card. Must be non-zero.
    /// @param agentDidHash Hash of the owning agent DID. Must be non-zero.
    function anchor(bytes32 cidHash, bytes32 agentDidHash) external {
        if (cidHash == bytes32(0)) revert ZeroCidHash();
        if (agentDidHash == bytes32(0)) revert ZeroAgentDidHash();

        // The two guards below are the whole fix for the overwrite defect:
        // an existing anchor is a hard stop, not a value to replace.
        Anchor storage existing = _anchors[cidHash];
        if (existing.anchorer != address(0)) {
            revert AlreadyAnchored(cidHash, existing.anchorer);
        }

        uint256 count = anchorCount[msg.sender];
        if (count >= maxAnchorsPerAgent) {
            revert AnchorLimitReached(msg.sender, maxAnchorsPerAgent);
        }

        _anchors[cidHash] = Anchor({
            anchorer: msg.sender,
            agentDidHash: agentDidHash,
            anchoredAtBlock: uint64(block.number),
            anchoredAtTime: uint64(block.timestamp)
        });
        _agentAnchors[msg.sender].push(cidHash);
        anchorCount[msg.sender] = count + 1;

        emit Anchored(cidHash, agentDidHash, msg.sender, block.number);
    }

    // ------------------------------------------------------------------ reads

    /// @notice Whether `cidHash` is anchored, and anchored *to `agentDidHash`*.
    ///
    /// // upstream v2.5.6 fix: upstream `verify` ignored the agent entirely, so a
    /// // real anchor for agent A verified as true for agent B. Both fields are
    /// // checked here, and the anchoring address is reported separately by
    /// // `anchorerOf` for callers that also want to know who wrote it.
    function verify(bytes32 cidHash, bytes32 agentDidHash) external view returns (bool) {
        Anchor storage a = _anchors[cidHash];
        return a.anchorer != address(0) && a.agentDidHash == agentDidHash;
    }

    /// @notice Whether `cidHash` may still be anchored by anyone.
    function isAnchorable(bytes32 cidHash) external view returns (bool) {
        return _anchors[cidHash].anchorer == address(0);
    }

    /// @notice The permanent anchor record for `cidHash`.
    /// @dev Reverts with `UnknownAnchor` for an unknown digest — documented
    ///      choice; use `tryGetAnchor` for the non-reverting form.
    function getAnchor(bytes32 cidHash) external view returns (Anchor memory) {
        Anchor storage a = _anchors[cidHash];
        if (a.anchorer == address(0)) revert UnknownAnchor(cidHash);
        return a;
    }

    /// @notice Non-reverting variant of `getAnchor`.
    /// @return found False when the digest has never been anchored.
    function tryGetAnchor(bytes32 cidHash)
        external
        view
        returns (bool found, Anchor memory anchor_)
    {
        Anchor storage a = _anchors[cidHash];
        found = a.anchorer != address(0);
        anchor_ = a;
    }

    /// @notice Address that anchored `cidHash`, or `address(0)` if unknown.
    function anchorerOf(bytes32 cidHash) external view returns (address) {
        return _anchors[cidHash].anchorer;
    }

    /// @notice Total anchors created by `agent` (bounded by the cap).
    function anchorsOfCount(address agent) external view returns (uint256) {
        return _agentAnchors[agent].length;
    }

    /// @notice A page of `agent`'s anchors.
    /// @dev // upstream v2.5.6 fix: paginated. Upstream returned (or rather
    ///      accumulated) the whole unbounded array; a caller that reads it
    ///      on-chain would pay gas proportional to the agent's entire history.
    ///      `limit` is clamped to the remaining entries, and a zero `limit`
    ///      yields an empty page rather than reverting.
    /// @param offset First index to return.
    /// @param limit Maximum entries to return.
    function anchorsOf(address agent, uint256 offset, uint256 limit)
        external
        view
        returns (bytes32[] memory page)
    {
        bytes32[] storage all = _agentAnchors[agent];
        uint256 total = all.length;
        if (offset > total) revert PageOutOfRange(offset, limit, total);

        uint256 remaining = total - offset;
        uint256 count = limit < remaining ? limit : remaining;
        page = new bytes32[](count);
        for (uint256 i = 0; i < count; ++i) {
            page[i] = all[offset + i];
        }
    }
}
