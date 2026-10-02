# Contracts

The on-chain settlement layer for NewAgentUniverseByDeepSeek. It replaces the
four `.sol` files that upstream agent-universe v2.5.6 shipped with no compiler
config, no tests, no vendored dependencies and no deploy script — of which three
were not deployable at all.

| File | Replaces | Purpose |
| --- | --- | --- |
| `src/GovernanceToken.sol` | `GovernanceToken.sol` | Fixed-supply ERC-20 with real vote checkpointing |
| `src/AgentCardAnchor.sol` | `AgentCardAnchor.sol` | Write-once, DID-bound agent-card anchors |
| `src/Settlement.sol` | `PoCVSettlement.sol` | Escrowed task settlement in integer minor units |
| `src/ReputationRegistry.sol` | `ReputationBridge.sol` | Bounded, epoch-keyed reputation in basis points |
| `src/base/Ownable.sol` | — (vendored) | Two-step ownership handshake |
| `src/base/ReentrancyGuard.sol` | — (vendored) | Single-slot reentrancy lock |
| `src/base/ERC20.sol` | — (vendored) | Minimal ERC-20 with a balance-mutation hook |

## Units

Every monetary value in this tree is an **integer count of minor units**, six
decimal places, matching `crates/nau-core/src/domain/money.rs`
(`DECIMALS = 6`, `MINOR_UNITS_PER_MAJOR = 1_000_000`). One whole NAU is
`1_000_000` on-chain units, and `ERC20.decimals()` returns `6` so the two agree
without a scaling step at the boundary.

There is no float anywhere, and that is not stylistic. The canonical-payload
rules pinned in `conformance/vectors.json` reject non-integer numbers outright:

> Floats are refused outright. This is the single most important cross-language
> fix: 100 vs 100.0 vs 1e2 format differently in Rust, Python and JavaScript, so
> a signed payload containing a float cannot be reproduced byte-for-byte. Money
> therefore travels as integer minor units.

A contract that took `1.5e18`-style fixed-point amounts would put a second,
disagreeing representation of the same quantity on the wire. So it does not.

## Dependencies

Exactly one, and only for tests and the deploy script:

```sh
cd contracts
forge install foundry-rs/forge-std@v1.9.4
```

(With git submodules in use, add `--no-commit` to stop forge from creating its
own commit. The tag is pinned either way — see `remappings` in
`foundry.toml`.)

`foundry.toml` maps `forge-std/=lib/forge-std/src/`. **OpenZeppelin is
deliberately not a dependency.** The three bases this tree needs total ~250
lines, they are in `src/base/`, and keeping them local means:

* a production build contains no third-party bytecode at all;
* there is no remapping, no submodule and no network fetch to get wrong;
* the ownership model is a two-step handshake with an explicit
  `acceptOwnership`, rather than inheriting whatever the pinned OZ major does.

## Building and testing

```sh
cd contracts
forge --version          # forge 0.2.0 or newer
forge build --sizes
forge test -vvv
forge fmt --check
```

`foundry.toml` pins `solc_version = "0.8.24"` and `evm_version = "cancun"`, so a
local build and the `contracts` job in `.github/workflows/ci.yml` compile the
same bytecode with the same compiler.

## Deploying

```sh
cd contracts
cp deploy.config.example.json deploy.config.json    # then edit every field
export RPC_URL=...
forge script script/Deploy.s.sol:Deploy \
  --rpc-url "$RPC_URL" --broadcast --verify --private-key "$PRIVATE_KEY"
```

`DEPLOY_CONFIG` overrides the config path. Signing is the caller's job: the
script never reads a raw key out of an environment variable itself.

## The version rule

`contracts/VERSION` is a **copy** of the repository-root `VERSION`, and
`VERSION` is the single source of truth — the same value that
`[workspace.package] version` carries in `Cargo.toml` and that
`crates/nau-core/tests/version_consistency.rs` already asserts against.

`script/Deploy.s.sol` reads `contracts/VERSION` at run time (via
`vm.projectRoot()` and `vm.readFile`) and **refuses to deploy** unless the
`version` field in the deploy config is byte-identical to it. The version that
was deployed is emitted as `VersionDeployed(string)`, so a release can be
reconstructed from the broadcast transcript alone.

Nothing restates the version in a second place that could drift: the CI
`contracts` job fails if `contracts/VERSION` != the root `VERSION`, and the
`version` job fails if the root `VERSION` != `[workspace.package] version`.

## Upstream defect ledger

Every fix is marked in the source with a `// upstream v2.5.6 fix:` comment. The
short version:

### `GovernanceToken.sol`

* `delegateVotes` did `votes[msg.sender] -= amount` while `votes` was never
  incremented, so it reverted unconditionally under checked arithmetic.
  **Fixed:** real per-account `Checkpoint[]` history, with `delegate`,
  `getVotes` and `getPastVotes(account, blockNumber)` in the standard
  Compound/`ERC20Votes` shape.
* `onlyOwner` was declared and never applied.
  **Fixed:** `mint` is owner-only and ownership is a real two-step handshake.
* `holders.push(to)` on every first receipt, into an array nothing reads.
  **Fixed:** the array is gone. Vote history lives in checkpoints that are
  actually queried.
* Votes did not follow transfers.
  **Fixed:** the ERC-20 `_update` hook moves votes from the sender's delegate to
  the recipient's delegate.

### `AgentCardAnchor.sol`

* `anchor()` was **unauthenticated and overwrote** `anchors[cidHash]`, so anyone
  could become the reported `anchorer` of anyone's card.
  **Fixed:** first-write-wins and permanent; a re-anchor reverts with
  `AlreadyAnchored`. There is no admin override.
* `verify(cidHash)` returned `anchoredAt > 0`, proving nothing.
  **Fixed:** `verify(cidHash, agentDidHash)` checks both.
* `agentAnchors[msg.sender].push(...)` was unbounded.
  **Fixed:** a constructor-set `maxAnchorsPerAgent` cap, plus a paginated
  `anchorsOf(address, offset, limit)`.

### `Settlement.sol`

* `createTask` was `payable` and never read `msg.value`, so a task could promise
  `type(uint256).max` with zero funding. **Fixed:** `msg.value == rewardAmount`,
  and a zero reward is refused.
* `verifyTask` / `disputeTask` had no access control.
  **Fixed:** a quorum of distinct owner-managed verifiers, and disputes limited
  to the task's requester or executor.
* `settleTask` called out with value before updating `totalStaked`, with no
  reentrancy guard. **Fixed:** all state before any interaction, `nonReentrant`
  everywhere, and a pull-payment `withdrawCredits` instead of a push.
* `acceptTask` allowed the requester to accept its own task.
  **Fixed:** `RequesterCannotExecute`, in both `acceptTask` and `assignTask`.
* A disputed task still paid the executor in full.
  **Fixed:** `resolveDispute` must pick `RefundRequester`, `PayExecutor` or
  `SlashExecutor`, and slashing really moves the stake.
* Settlement could pay `address(0)` when no executor was assigned.
  **Fixed:** the executor must be set, and `Verified` is unreachable without
  one.
* `totalStaked` was written and never read. **Fixed:** removed; the property
  that matters is `address(this).balance >= totalCreditsLocked + lockedEscrow`,
  asserted by `invariant_settlementBalanceCoversObligations` in
  `test/SettlementInvariant.t.sol`.

### `ReputationRegistry.sol`

* `addVerifier` was `onlyVerifier`, so any verifier could mint unlimited
  verifiers; nothing could be removed and there was no owner.
  **Fixed:** owner-only add/remove, constructor-set `maxVerifiers`, two-step
  ownership.
* Reputation was an arbitrary `uint32` while the off-chain model is basis
  points. **Fixed:** every dimension is validated `<= 10_000`, reverting with
  `ScoreAboveBps`.
* `snapshots[].push` was unbounded.
  **Fixed:** one snapshot per agent per epoch, reverting on a duplicate, with a
  `latestEpoch` accessor.
* The event emitted 1 of 4 dimensions.
  **Fixed:** `ReputationRecorded` carries all four, plus epoch and verifier.
* `getLatestReputation` reverted for an unknown agent.
  **Fixed:** it returns a zero-valued struct; `hasReputation` is the
  discriminator between "no data" and "reported as zero".

## Tests

`test/` contains one suite per contract. Test names encode the defect they
cover, so a regression names itself:

```
test_createTask_revertsWhenMsgValueDoesNotEqualReward
test_verifyTask_revertsForNonVerifier
test_verifyTask_requiresAQuorumOfDistinctVerifiers
test_disputeTask_revertsForStranger
test_settleTask_cannotReenter
test_acceptTask_revertsForRequester
test_dispute_canSlashExecutor
test_slashedExecutorEarnsLessThanASuccessfulOne
test_anchor_isFirstWriteWins_andCannotBeOverwritten
test_addVerifier_revertsForNonOwner_andHonoursCap
test_recordReputation_revertsAboveTenThousandBps
test_recordReputation_isOneSnapshotPerEpoch
test_delegateVotes_actuallyAccumulatesAndMoves
test_getPastVotes_isHistoricalNotCurrent
```

Plus the required property tests:

* `invariant_settlementBalanceCoversObligations` — the solvency invariant,
  driven by the random-operation handler in the same file.
* `testFuzz_settlementConservesValue` and `testFuzz_refundConservesValue` —
  conservation along the settlement and refund paths.
