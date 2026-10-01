"""Model tests: exact money, the task state table, and the signed structures."""

from __future__ import annotations

import unittest

try:  # discovered as a package by run_tests.py
    from ._support import CONFORMANCE_SEED  # noqa: F401 - parity with the suite
except ImportError:  # pragma: no cover - run as a plain script
    from _support import CONFORMANCE_SEED  # noqa: F401

from nau_sdk import (
    AgentCard,
    AmountError,
    AuthorizationError,
    Bid,
    Did,
    DidError,
    Dispute,
    DisputeOutcome,
    EvidenceGrade,
    Identity,
    Ledger,
    Money,
    OverflowError,
    Pricing,
    ResultEnvelope,
    SignatureError,
    Skill,
    Sla,
    TASK_STATES,
    Task,
    TaskId,
    TaskSpec,
    TaskState,
    TransitionError,
    ValidationError,
    VerificationPolicy,
    canonical_json,
    classify_task_state,
    major,
)

I64_MIN = -(2**63)
I64_MAX = 2**63 - 1


class TestMoneyExactness(unittest.TestCase):
    def test_parse_never_touches_a_float(self) -> None:
        self.assertEqual(Money.parse("0.1").minor, 100_000)
        self.assertEqual(Money.parse("1").minor, 1_000_000)
        self.assertEqual(Money.parse("12.5").minor, 12_500_000)
        self.assertEqual(Money.parse("-0.000001").minor, -1)
        self.assertEqual(Money.parse("+7").minor, 7_000_000)
        self.assertEqual(Money.parse(".5").minor, 500_000)
        self.assertEqual(Money.parse("5.").minor, 5_000_000)
        self.assertEqual(Money.parse(" 3.25 ").minor, 3_250_000)

    def test_the_classic_float_trap_does_not_apply(self) -> None:
        tenth = Money.parse("0.1")
        fifth = Money.parse("0.2")
        third = Money.parse("0.3")
        self.assertEqual(tenth.minor, 100_000)
        self.assertEqual(tenth.checked_add(fifth), third)
        self.assertEqual(tenth + fifth, third)
        # And the float version really is broken, which is the point.
        self.assertNotEqual(0.1 + 0.2, 0.3)

    def test_no_float_can_be_constructed(self) -> None:
        for value in (1.0, 0.5, "1"):
            with self.subTest(value=value):
                with self.assertRaises(AmountError):
                    Money(value)  # type: ignore[arg-type]

    def test_rejects_non_numeric_and_imprecise_input(self) -> None:
        for text in (
            "1.0000001",  # 7 decimal places
            "",
            "-",
            "+",
            "abc",
            "1e6",
            "1E6",
            "1,000",
            "NaN",
            "inf",
            "0x10",
            "1.2.3",
            "1 000",
            "٣",
            "1_000",
        ):
            with self.subTest(text=text):
                with self.assertRaises(AmountError):
                    Money.parse(text)

    def test_integer_overflow_is_refused_at_construction(self) -> None:
        with self.assertRaises(AmountError):
            Money(I64_MAX + 1)
        with self.assertRaises(AmountError):
            Money.parse(str(10**30))

    def test_checked_arithmetic_reports_overflow_rather_than_wrapping(self) -> None:
        self.assertRaises(AmountError, Money.max().checked_add, Money(1))
        self.assertRaises(AmountError, Money(I64_MIN).checked_sub, Money(1))
        self.assertRaises(AmountError, Money.max().checked_mul_int, 2)
        self.assertRaises(AmountError, Money(I64_MIN).checked_neg)

    def test_magnitude_of_i64_min_does_not_raise(self) -> None:
        self.assertEqual(Money(I64_MIN).abs_minor(), I64_MAX)
        self.assertTrue(Money(I64_MIN).to_decimal_string().startswith("-"))

    def test_decimal_string_round_trips_exactly(self) -> None:
        for text in (
            "0",
            "1",
            "-1",
            "0.000001",
            "-0.000001",
            "12.5",
            "1000",
            "-1000.25",
            "999999.999999",
        ):
            with self.subTest(text=text):
                money = Money.parse(text)
                self.assertEqual(money.to_decimal_string(), text)
                self.assertEqual(Money.parse(money.to_decimal_string()), money)

    def test_split_conserves_value_with_an_explicit_remainder(self) -> None:
        pot = Money.parse("10")
        share, remainder = pot.split(3)
        self.assertEqual(share.minor, 3_333_333)
        self.assertEqual(remainder.minor, 1)
        self.assertEqual(share.checked_mul_int(3).checked_add(remainder), pot)
        self.assertRaises(AmountError, pot.split, 0)

    def test_money_serializes_as_a_json_integer(self) -> None:
        # This is what makes Money survive the canonical layer, which refuses
        # floats outright.
        self.assertEqual(canonical_json({"amt": Money.parse("1.5")}), '{"amt":1500000}')
        self.assertEqual(canonical_json({"amt": Money(0)}), '{"amt":0}')

    def test_predicates_and_defaults(self) -> None:
        self.assertTrue(Money(0).is_zero())
        self.assertFalse(Money(0).is_positive())
        self.assertTrue(Money(1).is_positive())
        self.assertTrue(Money(-1).is_negative())
        self.assertEqual(Money.zero().minor, 0)
        self.assertEqual(major(50).minor, 50_000_000)
        self.assertEqual(Money.from_major_units(2).minor, 2_000_000)

    def test_money_is_not_a_float_even_after_division_like_maths(self) -> None:
        self.assertIsInstance(Money.parse("0.1").minor, int)
        self.assertNotIsInstance(Money.parse("0.1").minor, float)


class TestTaskStateTable(unittest.TestCase):
    EXPECTED = {
        "open": {"matched", "cancelled", "no_quorum"},
        "matched": {"running", "open", "cancelled", "disputed"},
        "running": {"submitted", "disputed", "cancelled"},
        "submitted": {"verifying", "disputed"},
        "verifying": {"accepted", "rework", "no_quorum", "disputed"},
        "rework": {"running", "open", "cancelled"},
        "accepted": {"settled", "disputed"},
        "disputed": {"settled", "slashed", "accepted", "cancelled"},
        "no_quorum": {"open", "cancelled"},
        "settled": set(),
        "slashed": set(),
        "cancelled": set(),
    }

    def test_there_are_exactly_twelve_states(self) -> None:
        self.assertEqual(len(TASK_STATES), 12)
        self.assertEqual(len(set(TASK_STATES)), 12)
        self.assertEqual(set(TASK_STATES), set(self.EXPECTED))

    def test_the_full_transition_table(self) -> None:
        for source, allowed in self.EXPECTED.items():
            for target in self.EXPECTED:
                with self.subTest(source=source, target=target):
                    self.assertEqual(
                        TaskState(source).can_transition_to(TaskState(target)),
                        target in allowed,
                        f"{source} -> {target}",
                    )

    def test_the_two_recovery_edges_upstream_lacks(self) -> None:
        self.assertTrue(TaskState.NO_QUORUM.can_transition_to(TaskState.OPEN))
        self.assertTrue(TaskState.REWORK.can_transition_to(TaskState.RUNNING))

    def test_terminal_states_reject_everything(self) -> None:
        for terminal in (TaskState.SETTLED, TaskState.SLASHED, TaskState.CANCELLED):
            self.assertTrue(terminal.is_terminal())
            for target in TASK_STATES:
                with self.subTest(terminal=terminal, target=target):
                    self.assertFalse(terminal.can_transition_to(target))

    def test_non_terminal_states_are_not_terminal(self) -> None:
        for state in TASK_STATES:
            if state in (TaskState.SETTLED, TaskState.SLASHED, TaskState.CANCELLED):
                continue
            self.assertFalse(state.is_terminal(), state)

    def test_every_non_terminal_state_has_an_exit(self) -> None:
        for state in TASK_STATES:
            if state.is_terminal():
                continue
            with self.subTest(state=state):
                self.assertTrue(
                    any(state.can_transition_to(t) for t in TASK_STATES),
                    f"{state} is a dead end",
                )

    def test_the_happy_path_is_walkable(self) -> None:
        path = [
            TaskState.OPEN,
            TaskState.MATCHED,
            TaskState.RUNNING,
            TaskState.SUBMITTED,
            TaskState.VERIFYING,
            TaskState.ACCEPTED,
            TaskState.SETTLED,
        ]
        for current, following in zip(path, path[1:]):
            self.assertTrue(current.can_transition_to(following))

    def test_transition_raises_for_illegal_moves(self) -> None:
        with self.assertRaises(TransitionError):
            TaskState.OPEN.transition(TaskState.SETTLED, "t1")
        with self.assertRaises(TransitionError):
            TaskState.SETTLED.transition(TaskState.OPEN)

    def test_reapplying_the_same_state_is_a_no_op(self) -> None:
        self.assertEqual(TaskState.OPEN.transition(TaskState.OPEN), TaskState.OPEN)
        self.assertEqual(
            TaskState.SETTLED.transition(TaskState.SETTLED), TaskState.SETTLED
        )

    def test_parse_and_classify(self) -> None:
        self.assertEqual(TaskState.parse("  OPEN "), TaskState.OPEN)
        self.assertEqual(classify_task_state(TaskState.RUNNING), TaskState.RUNNING)
        self.assertEqual(classify_task_state("running"), TaskState.RUNNING)
        with self.assertRaises(ValidationError):
            TaskState.parse("arbitration")
        with self.assertRaises(ValidationError):
            classify_task_state(7)

    def test_states_serialize_as_their_wire_names(self) -> None:
        self.assertEqual(canonical_json({"state": TaskState.NO_QUORUM}), '{"state":"no_quorum"}')


class _Fixtures(unittest.TestCase):
    """Shared builders for the model tests."""

    @staticmethod
    def identity(seed_byte: int = 11) -> Identity:
        return Identity.from_seed(bytes([seed_byte] * 32))

    @staticmethod
    def spec(identity: Identity) -> TaskSpec:
        return TaskSpec(
            goal="translate the document",
            context="source is English, target is Chinese",
            done=["all sections translated"],
            todo=["read source", "translate"],
            owner=identity.did,
        )

    @classmethod
    def task(cls, identity: Identity, **overrides: object) -> Task:
        task = Task.draft(
            task_id=TaskId.parse("task-abc"),
            spec=cls.spec(identity),
            required_skills=["translation"],
            budget=major(50),
            requester_key=identity.public_key,
            signed_at=1_700_000_000,
            nonce=1,
            verification=VerificationPolicy.committee(4, 1),
            **overrides,  # type: ignore[arg-type]
        )
        task.sign(identity)
        return task

    @classmethod
    def card(cls, identity: Identity) -> AgentCard:
        return AgentCard.draft(
            identity,
            "Translator",
            [Skill.new("translation", 1)],
            major(100),
            1_700_000_000,
            1,
        )


class TestTaskSpec(_Fixtures):
    def test_the_six_documented_fields_are_what_is_validated(self) -> None:
        spec = self.spec(self.identity())
        self.assertEqual(spec.gaps(), [])
        spec.validate()

        cases = [
            ({"goal": "  "}, "goal"),
            ({"context": ""}, "context"),
            ({"done": []}, "done"),
            ({"done": ["  "]}, "done"),
            ({"todo": []}, "todo"),
        ]
        for overrides, prefix in cases:
            with self.subTest(prefix=prefix):
                broken = TaskSpec(
                    goal=overrides.get("goal", spec.goal),
                    context=overrides.get("context", spec.context),
                    done=overrides.get("done", spec.done),
                    todo=overrides.get("todo", spec.todo),
                    owner=spec.owner,
                )
                self.assertTrue(any(g.startswith(prefix) for g in broken.gaps()))
                with self.assertRaises(ValidationError):
                    broken.validate()

    def test_trace_is_optional(self) -> None:
        spec = self.spec(self.identity())
        spec.trace = None
        self.assertEqual(spec.gaps(), [])


class TestTask(_Fixtures):
    def test_a_well_formed_task_signs_and_verifies(self) -> None:
        identity = self.identity()
        task = self.task(identity)
        task.validate_and_verify()
        self.assertEqual(task.state, TaskState.OPEN)

    def test_non_positive_budget_is_rejected(self) -> None:
        identity = self.identity()
        task = self.task(identity)
        task.budget = Money(0)
        self.assertRaises(AmountError, task.validate)
        task.budget = Money(-1)
        self.assertRaises(AmountError, task.validate)

    def test_a_task_cannot_claim_someone_elses_did(self) -> None:
        identity = self.identity()
        task = self.task(identity)
        task.spec.owner = self.identity(9).did
        with self.assertRaises(DidError):
            task.validate()

    def test_deadlines_are_enforced_where_upstream_ignored_them(self) -> None:
        identity = self.identity()
        task = self.task(identity, deadline=1_700_000_500)
        self.assertFalse(task.is_expired(1_700_000_400))
        self.assertFalse(task.is_expired(1_700_000_500))
        self.assertTrue(task.is_expired(1_700_000_501))
        task.signed_at = 1_700_000_600
        self.assertRaises(ValidationError, task.validate)

    def test_signing_as_another_identity_is_refused(self) -> None:
        identity = self.identity()
        task = self.task(identity)
        with self.assertRaises(AuthorizationError):
            task.sign(self.identity(3))

    def test_transition_advances_the_state(self) -> None:
        identity = self.identity()
        task = self.task(identity)
        task.transition(TaskState.MATCHED)
        task.transition("running")
        self.assertEqual(task.state, TaskState.RUNNING)
        with self.assertRaises(TransitionError):
            task.transition(TaskState.SETTLED)

    def test_task_ids_are_restricted_to_a_safe_charset(self) -> None:
        self.assertEqual(TaskId.parse("task-abc_123"), "task-abc_123")
        for bad in ("", "has space", "has/slash", "x" * 65, "é"):
            with self.subTest(bad=bad):
                self.assertRaises(ValidationError, TaskId.parse, bad)
        generated = TaskId.generate()
        self.assertTrue(str(generated).startswith("task-"))
        TaskId.parse(generated)


class TestVerificationPolicy(unittest.TestCase):
    def test_the_bft_relation_is_checked(self) -> None:
        VerificationPolicy.committee(4, 1).validate()
        VerificationPolicy.committee(7, 2).validate()
        with self.assertRaises(ValidationError):
            VerificationPolicy.committee(3, 1)
        with self.assertRaises(ValidationError):
            VerificationPolicy.committee(1, 1_431_655_766)

    def test_quorum(self) -> None:
        self.assertEqual(VerificationPolicy.committee(7, 2).quorum(), 5)
        self.assertEqual(VerificationPolicy.requester_only().quorum(), 1)

    def test_serialization(self) -> None:
        self.assertEqual(
            canonical_json({"v": VerificationPolicy.committee(4, 1)}),
            '{"v":{"f":1,"kind":"committee","n":4}}',
        )
        self.assertEqual(
            canonical_json({"v": VerificationPolicy.requester_only()}),
            '{"v":{"kind":"requester_only"}}',
        )


class TestBid(_Fixtures):
    def _bid(self, task: Task, identity: Identity, price: Money) -> Bid:
        return Bid(
            task_id=task.id,
            bidder=identity.did,
            bidder_key=identity.public_key,
            price=price,
            eta_secs=60,
            confidence_bps=9_000,
            signed_at=1_700_000_100,
            nonce=1,
        )

    def test_a_non_positive_price_is_refused(self) -> None:
        identity = self.identity()
        task = self.task(identity)
        for price in (Money(0), Money(-100)):
            with self.subTest(price=price.minor):
                with self.assertRaises(AmountError):
                    self._bid(task, identity, price).validate_for(task)

    def test_a_bid_above_budget_is_refused(self) -> None:
        identity = self.identity()
        task = self.task(identity)
        with self.assertRaises(AmountError):
            self._bid(task, identity, major(51)).validate_for(task)
        self._bid(task, identity, major(40)).validate_for(task)

    def test_a_bid_is_bound_to_its_task(self) -> None:
        identity = self.identity()
        task = self.task(identity)
        bid = self._bid(task, identity, major(1))
        bid.task_id = TaskId.parse("other-task")
        with self.assertRaises(ValidationError):
            bid.validate_for(task)

    def test_confidence_and_eta_bounds(self) -> None:
        identity = self.identity()
        task = self.task(identity)
        bid = self._bid(task, identity, major(1))
        bid.confidence_bps = 10_001
        self.assertRaises(ValidationError, bid.validate_for, task)
        bid.confidence_bps = 5_000
        bid.eta_secs = 0
        self.assertRaises(ValidationError, bid.validate_for, task)

    def test_a_bid_signs_and_verifies(self) -> None:
        identity = self.identity()
        task = self.task(identity)
        bid = self._bid(task, identity, major(1))
        bid.sign(identity)
        bid.verify()
        bid.price = major(2)
        with self.assertRaises(SignatureError):
            bid.verify()


class TestResultEnvelope(_Fixtures):
    def _envelope(self, identity: Identity, grade: EvidenceGrade) -> ResultEnvelope:
        return ResultEnvelope(
            task_id=TaskId.parse("task-abc"),
            agent=identity.did,
            agent_key=identity.public_key,
            output_digest="a" * 64,
            summary="done",
            signed_at=1_700_000_200,
            nonce=1,
            evidence=grade,
        )

    def test_only_trustworthy_evidence_may_release_payment(self) -> None:
        identity = self.identity()
        envelope = self._envelope(identity, EvidenceGrade.UNVERIFIED)
        envelope.sign(identity)
        envelope.validate()
        with self.assertRaises(ValidationError):
            envelope.validate_for_settlement()

        for grade in (EvidenceGrade.CPU_PROTO, EvidenceGrade.VERIFIED):
            with self.subTest(grade=grade):
                good = self._envelope(identity, grade)
                good.sign(identity)
                good.validate_for_settlement()

    def test_the_default_grade_is_fail_closed(self) -> None:
        envelope = self._envelope(self.identity(), EvidenceGrade.UNVERIFIED)
        self.assertFalse(envelope.evidence.is_settlement_grade())
        self.assertEqual(EvidenceGrade.CPU_PROTO.label(), "cpu-proto")
        self.assertEqual(EvidenceGrade.parse("cpu-proto"), EvidenceGrade.CPU_PROTO)
        with self.assertRaises(ValidationError):
            EvidenceGrade.parse("trust me")

    def test_the_output_digest_must_be_a_sha256(self) -> None:
        identity = self.identity()
        envelope = self._envelope(identity, EvidenceGrade.VERIFIED)
        envelope.output_digest = "abc"
        self.assertRaises(ValidationError, envelope.validate)
        self.assertEqual(
            ResultEnvelope.digest_output(b"x"),
            "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881",
        )


class TestAgentCard(_Fixtures):
    def test_a_card_signs_and_verifies(self) -> None:
        identity = self.identity()
        card = self.card(identity)
        card.sign(identity)
        card.validate_and_verify()
        self.assertTrue(card.signature)

    def test_a_card_with_no_skills_is_rejected(self) -> None:
        card = self.card(self.identity())
        card.skills = []
        self.assertRaises(ValidationError, card.validate)

    def test_zero_or_negative_stake_is_rejected(self) -> None:
        card = self.card(self.identity())
        card.stake = Money(0)
        self.assertRaises(AmountError, card.validate)
        card.stake = Money(-1)
        self.assertRaises(AmountError, card.validate)

    def test_negative_price_is_rejected(self) -> None:
        card = self.card(self.identity())
        card.pricing = Pricing(unit_price=Money(-5))
        self.assertRaises(AmountError, card.validate)

    def test_duplicate_and_uppercase_skills_are_rejected(self) -> None:
        card = self.card(self.identity())
        card.skills = [Skill.new("translation", 1), Skill.new("translation", 2)]
        self.assertRaises(ValidationError, card.validate)
        card.skills = [Skill(id="Translation", version=1)]
        self.assertRaises(ValidationError, card.validate)

    def test_a_card_cannot_claim_someone_elses_did(self) -> None:
        card = self.card(self.identity())
        card.owner = self.identity(9).did
        with self.assertRaises(DidError):
            card.validate()

    def test_signing_as_another_identity_is_refused(self) -> None:
        card = self.card(self.identity())
        with self.assertRaises(AuthorizationError):
            card.sign(self.identity(3))

    def test_expiry_must_be_after_signing(self) -> None:
        card = self.card(self.identity())
        card.expires_at = card.signed_at
        self.assertRaises(ValidationError, card.validate)
        card.expires_at = card.signed_at + 1
        card.validate()

    def test_the_sla_bounds(self) -> None:
        sla = Sla(availability_bps=10_001)
        self.assertRaises(ValidationError, sla.validate)
        sla = Sla(max_concurrency=0)
        self.assertRaises(ValidationError, sla.validate)
        Sla().validate()


class TestDisputes(_Fixtures):
    def _dispute(self) -> Dispute:
        complainant = self.identity(5)
        return Dispute(
            id="d1",
            task_id=TaskId.parse("task-abc"),
            complainant=complainant.did,
            complainant_key=complainant.public_key,
            respondent=self.identity(6).did,
            reason="never delivered",
            signed_at=1_700_000_300,
            nonce=1,
        )

    def test_a_dispute_signs_and_verifies(self) -> None:
        dispute = self._dispute()
        dispute.sign(self.identity(5))
        dispute.verify()
        dispute.validate()

    def test_a_party_cannot_dispute_itself(self) -> None:
        dispute = self._dispute()
        dispute.respondent = dispute.complainant
        self.assertRaises(ValidationError, dispute.validate)

    def test_a_guilty_verdict_must_actually_punish(self) -> None:
        arbitrator = self.identity(7)
        outcome = DisputeOutcome(
            dispute_id="d1",
            task_id=TaskId.parse("task-abc"),
            guilty=True,
            slash_amount=Money(0),
            ruling="at fault",
            arbitrator=arbitrator.did,
            arbitrator_key=arbitrator.public_key,
            signed_at=1,
            nonce=1,
        )
        with self.assertRaises(ValidationError):
            outcome.validate()
        outcome.slash_amount = major(10)
        outcome.sign(arbitrator)
        outcome.validate()
        outcome.verify()

    def test_a_not_guilty_verdict_must_not_slash(self) -> None:
        arbitrator = self.identity(7)
        outcome = DisputeOutcome(
            dispute_id="d1",
            task_id=TaskId.parse("task-abc"),
            guilty=False,
            slash_amount=major(1),
            ruling="innocent",
            arbitrator=arbitrator.did,
            arbitrator_key=arbitrator.public_key,
            signed_at=1,
            nonce=1,
        )
        self.assertRaises(ValidationError, outcome.validate)


class TestLedger(unittest.TestCase):
    def test_conservation_is_an_integer_equality(self) -> None:
        ledger = Ledger()
        ledger.deposit("alice", Money.parse("0.1"))
        ledger.deposit("bob", Money.parse("0.2"))
        ledger.assert_conserved()
        self.assertEqual(ledger.total(), Money.parse("0.3"))

    def test_transfers_preserve_the_total(self) -> None:
        ledger = Ledger()
        ledger.deposit("alice", major(10))
        before = ledger.total()
        ledger.transfer("alice", "bob", Money.parse("0.3"))
        self.assertEqual(ledger.total(), before)
        self.assertEqual(ledger.balance("bob"), Money.parse("0.3"))
        self.assertEqual(ledger.balance("alice"), Money.parse("9.7"))
        ledger.assert_conserved()

    def test_overdraft_is_refused_and_leaves_no_half_transfer(self) -> None:
        ledger = Ledger()
        ledger.deposit("alice", major(1))
        with self.assertRaises(AmountError):
            ledger.transfer("alice", "bob", major(2))
        self.assertEqual(ledger.balance("alice"), major(1))
        self.assertEqual(ledger.balance("bob"), Money(0))
        ledger.assert_conserved()

    def test_slashing_removes_value_from_the_ledger(self) -> None:
        ledger = Ledger()
        ledger.deposit("alice", major(10))
        ledger.slash("alice", major(4))
        self.assertEqual(ledger.balance("alice"), major(6))
        self.assertEqual(ledger.external_total(), major(6))
        ledger.assert_conserved()

    def test_the_hash_chain_detects_tampering(self) -> None:
        ledger = Ledger()
        ledger.deposit("alice", major(1))
        ledger.credit("alice", major(1))
        ledger.verify_chain()
        entries = list(ledger.entries())
        entries[1].amount = Money(major(2))
        # The entry's own hash no longer matches its body.
        with self.assertRaises(ValidationError):
            ledger.verify_chain()

    def test_the_chain_links_every_entry(self) -> None:
        ledger = Ledger()
        ledger.deposit("a", major(1))
        ledger.deposit("b", major(1))
        entries = ledger.entries()
        self.assertEqual(entries[0].prev_hash, "0" * 64)
        self.assertEqual(entries[1].prev_hash, entries[0].hash)

    def test_the_report_and_leaderboard(self) -> None:
        ledger = Ledger()
        ledger.deposit("a", major(1))
        ledger.deposit("b", major(3))
        report = ledger.conservation_report()
        self.assertTrue(report["balanced"])
        self.assertEqual(report["entries"], 2)
        board = ledger.leaderboard(1)
        self.assertEqual(board[0]["account"], "b")

    def test_negative_amounts_are_refused(self) -> None:
        ledger = Ledger()
        self.assertRaises(AmountError, ledger.deposit, "a", Money(-1))
        self.assertRaises(AmountError, ledger.credit, "a", Money(-1))
        self.assertRaises(ValidationError, ledger.deposit, "", Money(1))

    def test_amounts_may_be_strings_but_never_floats(self) -> None:
        ledger = Ledger()
        ledger.deposit("a", "1.5")
        self.assertEqual(ledger.balance("a"), Money.parse("1.5"))
        with self.assertRaises(AmountError):
            ledger.deposit("a", 1.5)  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
