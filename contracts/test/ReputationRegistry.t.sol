// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";

import {ReputationRegistry} from "../src/ReputationRegistry.sol";
import {Ownable} from "../src/base/Ownable.sol";

/// @notice Tests for `ReputationRegistry`, one per upstream v2.5.6 defect.
///
/// The upstream contract was `ReputationBridge.sol`.
contract ReputationRegistryTest is Test {
    ReputationRegistry internal registry;

    address internal ownerAddr = makeAddr("reputationOwner");
    address internal verifierOne = makeAddr("verifier1");
    address internal verifierTwo = makeAddr("verifier2");
    address internal stranger = makeAddr("stranger");
    address internal agent = makeAddr("agent");
    address internal otherAgent = makeAddr("otherAgent");

    ReputationRegistry.Reputation internal good;
    ReputationRegistry.Reputation internal perfect;

    function setUp() public {
        address[] memory verifiers = new address[](2);
        verifiers[0] = verifierOne;
        verifiers[1] = verifierTwo;
        registry = new ReputationRegistry(ownerAddr, verifiers, 2);

        good = ReputationRegistry.Reputation({
            quality: 8_000,
            reliability: 9_000,
            speed: 7_000,
            costEfficiency: 6_000
        });
        perfect = ReputationRegistry.Reputation({
            quality: 10_000,
            reliability: 10_000,
            speed: 10_000,
            costEfficiency: 10_000
        });
    }

    // ------------------------- defect: addVerifier was `onlyVerifier` (no owner)

    function test_addVerifier_revertsForNonOwner_andHonoursCap() public {
        // Upstream: any verifier could mint unlimited verifiers. A verifier is
        // still not the owner.
        vm.prank(verifierOne);
        vm.expectRevert(abi.encodeWithSelector(Ownable.NotOwner.selector, verifierOne));
        registry.addVerifier(stranger);

        // Even the seeded verifier seeding itself again is refused, on two
        // independent grounds (not owner, and already present).
        vm.prank(verifierOne);
        vm.expectRevert(abi.encodeWithSelector(Ownable.NotOwner.selector, verifierOne));
        registry.addVerifier(verifierOne);

        // The cap is a constructor parameter, and it is enforced.
        assertEq(registry.verifierCount(), 2);
        vm.prank(ownerAddr);
        vm.expectRevert(
            abi.encodeWithSelector(ReputationRegistry.TooManyVerifiers.selector, uint256(2))
        );
        registry.addVerifier(stranger);

        // Upstream had no removal path at all, so a hostile verifier was
        // permanent. Here the owner can retire one and free a slot.
        vm.prank(ownerAddr);
        registry.removeVerifier(verifierTwo);
        assertEq(registry.verifierCount(), 1);
        assertFalse(registry.isVerifier(verifierTwo));
        assertEq(registry.verifierAt(0), verifierOne);

        vm.prank(ownerAddr);
        registry.addVerifier(stranger);
        assertTrue(registry.isVerifier(stranger));

        // Removing a non-verifier is reported, not silently ignored.
        vm.prank(ownerAddr);
        vm.expectRevert(
            abi.encodeWithSelector(ReputationRegistry.VerifierNotPresent.selector, verifierTwo)
        );
        registry.removeVerifier(verifierTwo);
    }

    function test_constructor_rejectsAZeroVerifierCap() public {
        address[] memory none = new address[](0);
        vm.expectRevert(
            abi.encodeWithSelector(ReputationRegistry.TooManyVerifiers.selector, uint256(0))
        );
        new ReputationRegistry(ownerAddr, none, 0);
    }

    function test_ownership_isTwoStep() public {
        vm.prank(ownerAddr);
        registry.transferOwnership(stranger);
        assertEq(registry.owner(), ownerAddr, "a proposal is not a transfer");
        assertEq(registry.pendingOwner(), stranger);

        vm.prank(stranger);
        registry.acceptOwnership();
        assertEq(registry.owner(), stranger);

        vm.prank(ownerAddr);
        vm.expectRevert(abi.encodeWithSelector(Ownable.NotOwner.selector, ownerAddr));
        registry.addVerifier(agent);
    }

    // ---------------------------------- defect: arbitrary uint32, no 10000 bound

    function test_recordReputation_revertsAboveTenThousandBps() public {
        ReputationRegistry.Reputation memory tooBig = ReputationRegistry.Reputation({
            quality: 10_001,
            reliability: 1,
            speed: 1,
            costEfficiency: 1
        });

        vm.prank(verifierOne);
        vm.expectRevert(
            abi.encodeWithSelector(ReputationRegistry.ScoreAboveBps.selector, uint16(10_001), uint16(10_000))
        );
        registry.recordReputation(agent, 1, tooBig);

        // Every dimension is checked, not just the first: an off-chain model in
        // basis points cannot survive one dimension being 4 billion.
        ReputationRegistry.Reputation memory badFourth = ReputationRegistry.Reputation({
            quality: 1,
            reliability: 1,
            speed: 1,
            costEfficiency: type(uint16).max
        });
        vm.prank(verifierOne);
        vm.expectRevert(
            abi.encodeWithSelector(
                ReputationRegistry.ScoreAboveBps.selector, type(uint16).max, uint16(10_000)
            )
        );
        registry.recordReputation(agent, 1, badFourth);

        // The boundary itself is legal.
        vm.prank(verifierOne);
        registry.recordReputation(agent, 1, perfect);
        ReputationRegistry.Reputation memory stored = registry.getLatestReputation(agent);
        assertEq(stored.quality, 10_000);
        assertEq(stored.costEfficiency, 10_000);
    }

    function test_recordReputation_acceptsExactlyTheBasisPointRange() public {
        // The declared type is `uint16`, which is the *representation* bound
        // (max 65535); the *semantic* bound is 10000 basis points and is
        // enforced at runtime. A value in 0..10000 is stored as given — never
        // silently rescaled — and anything in 10001..65535 is refused, which is
        // the window upstream accepted and then compared against 10000-based
        // scores. (A caller holding a 1e18-scaled fraction must divide by 1e14
        // before calling; the type cannot carry 8.5e17 at all, and that is
        // intentional: it makes the mistake a compile error instead of a
        // production surprise.)
        vm.prank(verifierOne);
        registry.recordReputation(agent, 1, good);
        assertEq(registry.getLatestReputation(agent).quality, 8_000, "stored verbatim");

        ReputationRegistry.Reputation memory worst = ReputationRegistry.Reputation({
            quality: 0,
            reliability: 0,
            speed: 0,
            costEfficiency: 0
        });
        vm.prank(verifierOne);
        registry.recordReputation(agent, 2, worst);
        assertEq(registry.getLatestReputation(agent).quality, 0);

        ReputationRegistry.Reputation memory outOfRange = ReputationRegistry.Reputation({
            quality: type(uint16).max,
            reliability: 0,
            speed: 0,
            costEfficiency: 0
        });
        vm.prank(verifierOne);
        vm.expectRevert(
            abi.encodeWithSelector(
                ReputationRegistry.ScoreAboveBps.selector, type(uint16).max, uint16(10_000)
            )
        );
        registry.recordReputation(agent, 3, outOfRange);
    }

    // --------------------------------------- defect: unbounded `snapshots.push`

    function test_recordReputation_isOneSnapshotPerEpoch() public {
        vm.startPrank(verifierOne);
        registry.recordReputation(agent, 1, good);
        registry.recordReputation(agent, 2, perfect);
        vm.stopPrank();

        assertEq(registry.snapshotCount(agent), 2, "one row per epoch");
        assertEq(registry.latestEpoch(agent), 2);

        // A duplicate epoch is refused rather than appended: unbounded growth in
        // the upstream design came from exactly this call.
        vm.prank(verifierTwo);
        vm.expectRevert(
            abi.encodeWithSelector(ReputationRegistry.EpochAlreadyRecorded.selector, agent, uint64(2))
        );
        registry.recordReputation(agent, 2, good);

        // Going backwards is also refused, so the epoch key stays ordered.
        vm.prank(verifierTwo);
        vm.expectRevert(
            abi.encodeWithSelector(ReputationRegistry.EpochNotIncreasing.selector, uint64(2), uint64(1))
        );
        registry.recordReputation(agent, 1, good);

        assertEq(registry.snapshotCount(agent), 2, "no growth from either rejection");
    }

    function test_snapshots_areQueryableByIndexAndEpoch() public {
        vm.prank(verifierOne);
        registry.recordReputation(agent, 7, good);

        ReputationRegistry.Snapshot memory snap = registry.snapshotAt(agent, 0);
        assertEq(snap.epoch, 7);
        assertEq(snap.verifier, verifierOne);
        assertEq(snap.reputation.quality, 8_000);

        (bool found, ReputationRegistry.Snapshot memory byEpoch) = registry.snapshotByEpoch(agent, 7);
        assertTrue(found);
        assertEq(byEpoch.reputation.reliability, 9_000);

        (bool missing,) = registry.snapshotByEpoch(agent, 8);
        assertFalse(missing);
    }

    function test_latestEpoch_tracksTheHighestReportedEpoch() public {
        assertEq(registry.latestEpoch(agent), 0, "a fresh agent has no epoch");
        assertFalse(registry.hasReputation(agent));

        vm.prank(verifierOne);
        registry.recordReputation(agent, 41, good);
        assertEq(registry.latestEpoch(agent), 41);
        assertTrue(registry.hasReputation(agent));
    }

    function test_recordReputation_revertsForNonVerifier() public {
        // Anyone could report in the upstream design, and a removed verifier's
        // reports were never bounded either.
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(ReputationRegistry.NotAVerifier.selector, stranger));
        registry.recordReputation(agent, 1, good);

        vm.startPrank(ownerAddr);
        registry.removeVerifier(verifierOne);
        vm.stopPrank();

        vm.prank(verifierOne);
        vm.expectRevert(
            abi.encodeWithSelector(ReputationRegistry.NotAVerifier.selector, verifierOne)
        );
        registry.recordReputation(agent, 1, good);
    }

    function test_recordReputation_revertsForZeroAgent() public {
        vm.prank(verifierOne);
        // `ZeroAddress` is declared once, in the `Ownable` base, and inherited.
        // Qualifying it through the derived contract does not resolve it; naming
        // the declaring contract does. (Redeclaring it in the derived contract
        // was the original bug — Solidity rejects that as a conflict.)
        vm.expectRevert(Ownable.ZeroAddress.selector);
        registry.recordReputation(address(0), 1, good);
    }

    // -------------------------------------- defect: getLatestReputation reverted

    function test_getLatestReputation_returnsZerosForUnknownAgent() public {
        // Must not revert: both values below are the uninitialised struct.
        ReputationRegistry.Reputation memory unknown = registry.getLatestReputation(stranger);
        assertEq(unknown.quality, 0);
        assertEq(unknown.reliability, 0);
        assertEq(unknown.speed, 0);
        assertEq(unknown.costEfficiency, 0);

        // Unknown != "reported as zero": `hasReputation` is the discriminator.
        assertFalse(registry.hasReputation(stranger));
        assertEq(registry.snapshotCount(stranger), 0);
    }

    function test_getLatestReputation_isPerAgent() public {
        vm.prank(verifierOne);
        registry.recordReputation(agent, 1, good);
        vm.prank(verifierTwo);
        registry.recordReputation(otherAgent, 1, perfect);

        assertEq(registry.getLatestReputation(agent).quality, 8_000);
        assertEq(registry.getLatestReputation(otherAgent).quality, 10_000);
        assertEq(registry.latestEpoch(agent), 1);
        assertEq(registry.latestEpoch(otherAgent), 1);
    }

    // ------------------------------- defect: event emitted 1 of 4 dimensions

    function test_recordReputation_emitsAllFourDimensionsPlusEpochAndVerifier() public {
        vm.expectEmit(true, true, true, true, address(registry));
        emit ReputationRegistry.ReputationRecorded(
            agent, 9, verifierOne, uint16(8_000), uint16(9_000), uint16(7_000), uint16(6_000)
        );
        vm.prank(verifierOne);
        registry.recordReputation(agent, 9, good);
    }

    function test_isVerifierIsTheLiveSetNotAHistoricalOne() public {
        assertTrue(registry.isVerifier(verifierOne));
        assertTrue(registry.isVerifier(verifierTwo));
        assertFalse(registry.isVerifier(stranger));

        vm.prank(ownerAddr);
        registry.removeVerifier(verifierOne);
        assertFalse(registry.isVerifier(verifierOne));

        // A snapshot written before removal still names its author: history is
        // not rewritten by a membership change.
        vm.prank(verifierTwo);
        registry.recordReputation(agent, 1, good);
        assertEq(registry.snapshotAt(agent, 0).verifier, verifierTwo);
    }
}
