// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";

import {AgentCardAnchor} from "../src/AgentCardAnchor.sol";

/// @notice Assertions for the per-agent anchor cap.
contract AgentCardAnchorCapTest is Test {
    AgentCardAnchor internal anchors;

    address internal agent = makeAddr("agent");

    function setUp() public {
        anchors = new AgentCardAnchor(2);
    }

    function test_anchor_revertsOnceThePerAgentCapIsReached() public {
        vm.startPrank(agent);

        anchors.anchor(bytes32(uint256(1)), bytes32(uint256(0xA1)));
        anchors.anchor(bytes32(uint256(2)), bytes32(uint256(0xA1)));
        assertEq(anchors.anchorsOfCount(agent), 2);

        // // upstream v2.5.6 fix: the unbounded `agentAnchors[msg.sender].push`
        // // is now a capped, constant worst case.
        vm.expectRevert(
            abi.encodeWithSelector(AgentCardAnchor.AnchorLimitReached.selector, agent, uint256(2))
        );
        anchors.anchor(bytes32(uint256(3)), bytes32(uint256(0xA1)));

        vm.stopPrank();
    }

    function test_constructor_rejectsAZeroCap() public {
        vm.expectRevert(bytes("maxAnchorsPerAgent must be > 0"));
        new AgentCardAnchor(0);
    }
}

/// @notice Tests for `AgentCardAnchor`, one per upstream v2.5.6 defect.
contract AgentCardAnchorTest is Test {
    AgentCardAnchor internal anchors;

    address internal agentA = makeAddr("agentA");
    address internal agentB = makeAddr("agentB");
    address internal attacker = makeAddr("attacker");

    bytes32 internal constant CID = keccak256("QmExampleAgentCardCID");
    bytes32 internal constant DID_A = keccak256("did:nau:aaaa");
    bytes32 internal constant DID_B = keccak256("did:nau:bbbb");

    function setUp() public {
        anchors = new AgentCardAnchor(100);
        vm.roll(5_000);
    }

    /// @dev THE headline defect: upstream `anchor()` overwrote unconditionally,
    ///      so anyone could take over any existing anchor and become the
    ///      reported `anchorer` of a card they had never seen.
    function test_anchor_isFirstWriteWins_andCannotBeOverwritten() public {
        vm.prank(agentA);
        anchors.anchor(CID, DID_A);

        // The attacker tries to re-anchor the same digest as themselves.
        vm.prank(attacker);
        vm.expectRevert(
            abi.encodeWithSelector(AgentCardAnchor.AlreadyAnchored.selector, CID, agentA)
        );
        anchors.anchor(CID, DID_A);

        // A re-anchor that also swaps the DID hash must fail identically: the
        // digest is spent, no matter what is being claimed about it.
        vm.prank(attacker);
        vm.expectRevert(
            abi.encodeWithSelector(AgentCardAnchor.AlreadyAnchored.selector, CID, agentA)
        );
        anchors.anchor(CID, DID_B);

        // The original anchor is intact and still attributable.
        AgentCardAnchor.Anchor memory a = anchors.getAnchor(CID);
        assertEq(a.anchorer, agentA, "the first anchorer must remain the anchorer");
        assertEq(a.agentDidHash, DID_A);
        assertEq(anchors.anchorerOf(CID), agentA);
        assertFalse(anchors.isAnchorable(CID));
    }

    /// @dev Upstream `verify(cidHash)` returned `anchoredAt > 0`, which is true
    ///      for someone else's anchor too, so it proved nothing about ownership.
    function test_verify_checksBothTheDigestAndTheAgentDid() public {
        vm.prank(agentA);
        anchors.anchor(CID, DID_A);

        assertTrue(anchors.verify(CID, DID_A), "the true pair must verify");
        assertFalse(anchors.verify(CID, DID_B), "a different DID must not verify");
        assertFalse(anchors.verify(keccak256("other"), DID_A), "an unknown digest must not verify");
    }

    function test_anchor_revertsOnReAnchorWithADistinctError() public {
        vm.prank(agentA);
        anchors.anchor(CID, DID_A);

        // A distinct, specific error (not a bare require string) so off-chain
        // tooling can tell "already anchored" from "bad input".
        vm.prank(agentA);
        vm.expectRevert(
            abi.encodeWithSelector(AgentCardAnchor.AlreadyAnchored.selector, CID, agentA)
        );
        anchors.anchor(CID, DID_A);
    }

    function test_anchor_revertsForZeroInputs() public {
        vm.prank(agentA);
        vm.expectRevert(AgentCardAnchor.ZeroCidHash.selector);
        anchors.anchor(bytes32(0), DID_A);

        vm.prank(agentA);
        vm.expectRevert(AgentCardAnchor.ZeroAgentDidHash.selector);
        anchors.anchor(CID, bytes32(0));
    }

    function test_getAnchor_revertsForUnknownHash_andTryGetDoesNot() public {
        // Documented choice: `getAnchor` reverts, because a zero struct is
        // indistinguishable from a legitimate all-zero anchor.
        vm.expectRevert(abi.encodeWithSelector(AgentCardAnchor.UnknownAnchor.selector, CID));
        anchors.getAnchor(CID);

        (bool found, AgentCardAnchor.Anchor memory a) = anchors.tryGetAnchor(CID);
        assertFalse(found);
        assertEq(a.anchorer, address(0));
    }

    function test_anchorsOf_isPaginatedAndBounded() public {
        vm.startPrank(agentA);
        anchors.anchor(keccak256("cid-0"), DID_A);
        anchors.anchor(keccak256("cid-1"), DID_A);
        anchors.anchor(keccak256("cid-2"), DID_A);
        vm.stopPrank();

        assertEq(anchors.anchorsOfCount(agentA), 3);

        bytes32[] memory firstPage = anchors.anchorsOf(agentA, 0, 2);
        assertEq(firstPage.length, 2);
        assertEq(firstPage[0], keccak256("cid-0"));
        assertEq(firstPage[1], keccak256("cid-1"));

        // `limit` beyond the end is clamped, not reverted.
        bytes32[] memory tail = anchors.anchorsOf(agentA, 1, 100);
        assertEq(tail.length, 2);
        assertEq(tail[1], keccak256("cid-2"));

        // A zero limit yields an empty page.
        assertEq(anchors.anchorsOf(agentA, 0, 0).length, 0);

        // An offset past the end is a caller bug and is reported as one.
        vm.expectRevert(
            abi.encodeWithSelector(AgentCardAnchor.PageOutOfRange.selector, uint256(4), uint256(1), uint256(3))
        );
        anchors.anchorsOf(agentA, 4, 1);

        // Another agent's page is empty: anchors are per-anchorer.
        assertEq(anchors.anchorsOfCount(agentB), 0);
    }

    function test_anchorsAreIndependentPerAnchorer() public {
        vm.prank(agentA);
        anchors.anchor(CID, DID_A);
        vm.prank(agentB);
        anchors.anchor(keccak256("cid-b"), DID_B);

        assertEq(anchors.anchorsOfCount(agentA), 1);
        assertEq(anchors.anchorsOfCount(agentB), 1);
        assertEq(anchors.anchorCount(agentA), 1);
        assertEq(anchors.anchorCount(agentB), 1);
        assertTrue(anchors.verify(keccak256("cid-b"), DID_B));
        assertFalse(anchors.verify(keccak256("cid-b"), DID_A));
    }
}
