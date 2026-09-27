#!/usr/bin/env python3
"""Local, honest verification pass for the contracts/ + .github/ deliverable.

This script does NOT compile Solidity and does NOT run Foundry: neither `forge`
nor `solc` exists on this machine. What it can do is mechanical:

  * YAML-parse every workflow and the Dependabot config;
  * check every Solidity file for balanced (), {}, [] ignoring string and
    comment content;
  * check that every non-view/pure function that declares a return value has at
    least one `return` statement, and that every `returns (...)` tuple is either
    fully returned or explicitly assigned;
  * check the deploy config JSON parses and carries the VERSION value;
  * check contracts/VERSION == ./VERSION.

Exit code 0 means "the things a parser can check are fine", NOT "it compiles".
"""

from __future__ import annotations

import json
import pathlib
import re
import sys

# Never leave a __pycache__ directory behind: this script is run from CI against
# a checked-out tree, and an untracked artifact in a clean checkout is noise.
sys.dont_write_bytecode = True

ROOT = pathlib.Path(__file__).resolve().parents[1]
CONTRACTS = ROOT / "contracts"
WORKFLOWS = ROOT / ".github" / "workflows"

failures: list[str] = []
notes: list[str] = []


def fail(message: str) -> None:
    failures.append(message)


def note(message: str) -> None:
    notes.append(message)


# --------------------------------------------------------------------- YAML


def check_yaml() -> None:
    """Parse every workflow with the vendored mini-parser below.

    `yaml` is deliberately NOT imported: PyYAML is not installed in the
    environment this check runs in, and a check that silently skips itself when a
    dependency is missing is the exact failure mode this deliverable is supposed
    to eliminate (upstream's Python CI skipped 11 of 17 tests and went green).
    """
    targets = sorted(WORKFLOWS.glob("*.yml")) + sorted(WORKFLOWS.glob("*.yaml"))
    targets += [ROOT / ".github" / "dependabot.yml"]
    if not targets:
        fail("no workflow files found")
        return

    yaml_docs: dict[str, object] = {}
    for path in targets:
        try:
            docs = parse_yaml(path.read_text(encoding="utf-8"))
        except MiniYamlError as exc:
            fail(f"{path.relative_to(ROOT)}: invalid YAML: {exc}")
            continue
        if not isinstance(docs, dict) or not docs:
            fail(f"{path.relative_to(ROOT)}: parsed as an empty document")
            continue
        yaml_docs[path.name] = docs
        note(f"YAML ok: {path.relative_to(ROOT)} ({len(docs)} top-level keys)")

    ci = yaml_docs.get("ci.yml", {})
    jobs = set((ci.get("jobs") or {}).keys())
    required_jobs = {
        "rust",
        "python",
        "js",
        "conformance",
        "contracts",
        "version",
        "shellcheck",
    }
    missing = required_jobs - jobs
    if missing:
        fail(f"ci.yml is missing jobs: {sorted(missing)}")
    if "workflow_call" not in (ci.get("on") or {}):
        fail("ci.yml must declare `workflow_call` so release.yml can reuse it")
    rust_steps = _steps(ci, "rust")
    if not any("--locked" in (step.get("run") or "") for step in rust_steps):
        fail("ci.yml rust job has no --locked command")
    if not any(
        "cargo clippy" in (step.get("run") or "") and "-D warnings" in (step.get("run") or "")
        for step in rust_steps
    ):
        fail("ci.yml rust job does not run clippy with `-D warnings`")
    if not any(
        "cargo fmt --all --check" in (step.get("run") or "") for step in rust_steps
    ):
        fail("ci.yml rust job does not run `cargo fmt --all --check`")
    matrix_os = (
        (((ci.get("jobs") or {}).get("rust") or {}).get("strategy") or {})
        .get("matrix", {})
        .get("os", [])
    )
    for expected_os in ("ubuntu-latest", "macos-latest", "windows-latest"):
        if expected_os not in matrix_os:
            fail(f"ci.yml rust matrix is missing {expected_os}")
    if ci.get("env", {}).get("CARGO_BUILD_JOBS") is None:
        fail("ci.yml does not set CARGO_BUILD_JOBS")
    conformance_steps = _steps(ci, "conformance")
    if not any(
        "generate.mjs" in (step.get("run") or "") for step in conformance_steps
    ):
        fail("ci.yml conformance job does not run conformance/generate.mjs")
    if not any(
        "git diff --exit-code" in (step.get("run") or "") for step in conformance_steps
    ):
        fail("ci.yml conformance job does not diff the regenerated vectors")
    contracts_steps = _steps(ci, "contracts")
    contracts_runs = " ".join((step.get("run") or "") for step in contracts_steps)
    for expected in ("forge fmt --check", "forge build --sizes", "forge test -vvv"):
        if expected not in contracts_runs:
            fail(f"ci.yml contracts job does not run `{expected}`")

    # Assertions on parsed *values*, not just on the shape. These are what prove
    # the mini-parser actually recovered the content instead of returning None
    # for whole sections: each one names a scalar or list buried several levels
    # deep inside a nested mapping inside a sequence.
    if (ci.get("env") or {}).get("CARGO_BUILD_JOBS") != "2":
        fail(f"ci.yml CARGO_BUILD_JOBS parsed as {(ci.get('env') or {}).get('CARGO_BUILD_JOBS')!r}")
    if (ci.get("env") or {}).get("RUST_TOOLCHAIN") != "1.83.0":
        fail("ci.yml does not pin RUST_TOOLCHAIN to an exact version")
    rust_step_names = [step.get("name") for step in rust_steps]
    if not any("--locked" in (name or "") for name in rust_step_names):
        fail("ci.yml rust job has no named `--locked` step")
    checkouts = [
        step
        for step in rust_steps
        if (step.get("uses") or "").startswith("actions/checkout@")
    ]
    if len(checkouts) != 1:
        fail(f"ci.yml rust job has {len(checkouts)} checkout steps, expected 1")
    elif not re.fullmatch(r"actions/checkout@[0-9a-f]{40}", checkouts[0]["uses"]):
        fail("ci.yml rust checkout is not pinned to a commit SHA")
    if (ci.get("permissions") or {}).get("contents") != "read":
        fail("ci.yml must default to `permissions: contents: read`")
    if not any(
        "sdks/python/run_tests.py" in (step.get("run") or "") for step in _steps(ci, "python")
    ):
        fail("ci.yml python job does not run sdks/python/run_tests.py")
    if not any("sdks/js/test/run.js" in (step.get("run") or "") for step in _steps(ci, "js")):
        fail("ci.yml js job does not run sdks/js/test/run.js")
    if not any("shellcheck" in (step.get("run") or "") for step in _steps(ci, "shellcheck")):
        fail("ci.yml shellcheck job does not invoke shellcheck")
    if not any(
        "workspace.package" in (step.get("run") or "") for step in _steps(ci, "version")
    ):
        fail("ci.yml version job does not compare against [workspace.package] version")
    setup_python = [
        step
        for step in _steps(ci, "python")
        if (step.get("uses") or "").startswith("actions/setup-python@")
    ]
    if not setup_python or (setup_python[0].get("with") or {}).get("python-version") != "3.12":
        fail("ci.yml python job does not pin Python 3.12")
    setup_node = [
        step for step in _steps(ci, "js") if (step.get("uses") or "").startswith("actions/setup-node@")
    ]
    if not setup_node or (setup_node[0].get("with") or {}).get("node-version") != "22":
        fail("ci.yml js job does not pin Node 22")

    # The clippy gate must not be neutered, and no step may opt out of gating.
    # Comments are stripped first: this file *explains* the upstream `|| echo`
    # habit, and the explanation must not be mistaken for the defect.
    ci_text = (WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
    ci_code = "\n".join(
        line for line in ci_text.splitlines() if not line.lstrip().startswith("#")
    )
    if re.search(r"cargo clippy[^\n]*\|\|", ci_code):
        fail("ci.yml wraps cargo clippy in a `||` fallback (the upstream defect)")
    if "|| echo" in ci_code:
        fail("ci.yml contains an `|| echo` escape hatch")
    if "continue-on-error" in ci_code:
        fail("ci.yml contains `continue-on-error`, which makes a job non-gating")

    release = yaml_docs.get("release.yml", {})
    release_jobs = release.get("jobs") or {}
    if "verify" not in release_jobs:
        fail("release.yml has no `verify` job")
    else:
        uses = release_jobs["verify"].get("uses") or ""
        if "ci.yml" not in uses:
            fail("release.yml `verify` does not call .github/workflows/ci.yml")
    publish = release_jobs.get("publish") or {}
    if "prepare" not in (publish.get("needs") or []):
        fail("release.yml `publish` must `needs: prepare`")
    prepare = release_jobs.get("prepare") or {}
    if "guard" not in (prepare.get("needs") or []):
        fail("release.yml `prepare` must `needs: guard`")
    guard = release_jobs.get("guard") or {}
    if "verify" not in (guard.get("needs") or []):
        fail("release.yml `guard` must `needs: verify`")
    if (release.get("permissions") or {}).get("contents") != "write":
        fail("release.yml must declare workflow-level `permissions: contents: write`")
    on_release = release.get("on") or {}
    tags = (((on_release.get("push") or {}).get("tags")) or [])
    if tags != ["v*"]:
        fail("release.yml must trigger only on `v*` tags")
    guard_runs = " ".join((step.get("run") or "") for step in _steps(release, "guard"))
    if "VERSION" not in guard_runs:
        fail("release.yml guard job does not assert against the VERSION file")

    codeql = yaml_docs.get("codeql.yml", {})
    codeql_languages = set()
    for entry in (
        (((codeql.get("jobs") or {}).get("analyze") or {}).get("strategy") or {})
        .get("matrix", {})
        .get("include", [])
    ):
        codeql_languages.add(entry.get("language"))
    for language in ("rust", "javascript-typescript", "python"):
        if language not in codeql_languages:
            fail(f"codeql.yml does not analyse {language}")
    if not (codeql.get("on") or {}).get("schedule"):
        fail("codeql.yml has no weekly schedule")

    dependabot = yaml_docs.get("dependabot.yml", {})
    ecosystems = {
        (entry.get("package-ecosystem"), entry.get("directory"))
        for entry in (dependabot.get("updates") or [])
    }
    for expected in (
        ("cargo", "/"),
        ("npm", "/sdks/js"),
        ("pip", "/sdks/python"),
        ("github-actions", "/"),
    ):
        if expected not in ecosystems:
            fail(f"dependabot.yml is missing {expected}")

    # Every `uses:` must be pinned to a full-length commit SHA.
    for path in targets:
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            match = re.match(r"\s*uses:\s*(\S+)", line)
            if not match:
                continue
            ref = match.group(1)
            if ref.startswith("./"):
                continue
            if "@" not in ref:
                fail(f"{path.name}:{lineno}: `uses: {ref}` has no version pin")
                continue
            version = ref.rsplit("@", 1)[1]
            if not re.fullmatch(r"[0-9a-f]{40}", version):
                fail(f"{path.name}:{lineno}: `{ref}` is not pinned to a 40-char commit SHA")


def _steps(doc: dict, job: str) -> list[dict]:
    return ((doc.get("jobs") or {}).get(job) or {}).get("steps") or []


# ------------------------------------------------------- vendored mini-YAML


class MiniYamlError(ValueError):
    pass


def _mini_yaml_scalar(text: str):
    text = text.strip()
    # Strip an inline comment. GitHub workflow files are full of
    # `uses: actions/checkout@<sha> # v4.2.2`, and the comment must not become
    # part of the value.
    if not text.startswith(("'", '"')):
        hash_index = text.find(" #")
        if hash_index != -1:
            text = text[:hash_index].strip()
    if text == "" or text == "~" or text == "null":
        return None
    if text.startswith("[") and text.endswith("]"):
        inner = text[1:-1].strip()
        if not inner:
            return []
        return [_mini_yaml_scalar(part) for part in inner.split(",")]
    if (text.startswith('"') and text.endswith('"') and len(text) >= 2) or (
        text.startswith("'") and text.endswith("'") and len(text) >= 2
    ):
        return text[1:-1]
    if text in ("true", "false"):
        return text == "true"
    # A GitHub Actions `on:` key is the boolean-looking word `on` in YAML 1.1 and
    # the string `on` here; keeping it a string is what the callers expect.
    return text


def _mini_yaml_block(lines: list[str], start: int, indent: int):
    """Parse a mapping or sequence at `indent`, returning (value, next_index)."""
    index = start
    # Decide sequence vs mapping from the first meaningful line.
    while index < len(lines) and (lines[index].strip() == "" or lines[index].lstrip().startswith("#")):
        index += 1
    if index >= len(lines):
        return None, index
    is_sequence = lines[index].startswith(" " * indent + "-")
    value = [] if is_sequence else {}
    while index < len(lines):
        raw = lines[index]
        if raw.strip() == "" or raw.lstrip().startswith("#"):
            index += 1
            continue
        current = len(raw) - len(raw.lstrip(" "))
        if current < indent:
            break
        if current > indent:
            raise MiniYamlError(f"line {index + 1}: unexpected indent")
        body = raw.strip()
        if is_sequence:
            if not body.startswith("-"):
                break
            item = body[1:].strip()
            if not item:
                child, index = _mini_yaml_block(lines, index + 1, indent + 2)
                value.append(child)
                continue
            if ":" in item and not item.startswith(("'", '"', "[")):
                # A sequence item that starts an inline mapping: `- name: x`.
                key, _, rest = item.partition(":")
                entry = {}
                rest = rest.strip()
                if rest in ("|", ">"):
                    block, index = _mini_yaml_block_scalar(lines, index + 1, indent)
                    entry[key.strip()] = block
                    merged, index = _mini_yaml_block(lines, index, indent + 2)
                    if isinstance(merged, dict):
                        entry.update(merged)
                else:
                    entry[key.strip()] = _mini_yaml_scalar(rest)
                    merged, index = _mini_yaml_block(lines, index + 1, indent + 2)
                    if isinstance(merged, dict):
                        entry.update(merged)
                value.append(entry)
                continue
            value.append(_mini_yaml_scalar(item))
            index += 1
            continue

        if body.startswith("- "):
            break
        key, sep, rest = body.partition(":")
        if not sep:
            raise MiniYamlError(f"line {index + 1}: expected `key: value`, got {body!r}")
        key = _mini_yaml_scalar(key.strip())
        rest = rest.strip()
        if rest in ("|", ">", "|-", ">-"):
            block, index = _mini_yaml_block_scalar(lines, index + 1, indent)
            value[key] = block
            continue
        if rest.startswith("#"):
            rest = ""
        if rest == "":
            # A nested block, or a key with no value.
            probe = index + 1
            while probe < len(lines) and (
                lines[probe].strip() == "" or lines[probe].lstrip().startswith("#")
            ):
                probe += 1
            if probe < len(lines):
                nxt_indent = len(lines[probe]) - len(lines[probe].lstrip(" "))
                if nxt_indent > current:
                    child, index = _mini_yaml_block(lines, probe, nxt_indent)
                    value[key] = child
                    continue
            value[key] = None
            index += 1
            continue
        value[key] = _mini_yaml_scalar(rest)
        index += 1
    return value, index


def _mini_yaml_block_scalar(lines: list[str], start: int, parent_indent: int):
    """Collect the raw text of a `|` / `>` block scalar."""
    collected: list[str] = []
    index = start
    body_indent = None
    while index < len(lines):
        raw = lines[index]
        if raw.strip() == "":
            collected.append("")
            index += 1
            continue
        current = len(raw) - len(raw.lstrip(" "))
        if current <= parent_indent:
            break
        if body_indent is None:
            body_indent = current
        collected.append(raw[body_indent:])
        index += 1
    while collected and collected[-1] == "":
        collected.pop()
    return "\n".join(collected) + "\n", index


def parse_yaml(text: str):
    if "\t" in text.replace("\t", " ") and re.search(r"^\t", text, re.MULTILINE):
        raise MiniYamlError("tab indentation is not valid YAML")
    if "<<" in text and re.search(r"^\s*<<:", text, re.MULTILINE):
        raise MiniYamlError("merge keys are not supported by the mini-parser")
    lines = text.splitlines()
    value, index = _mini_yaml_block(lines, 0, 0)
    while index < len(lines):
        if lines[index].strip() and not lines[index].lstrip().startswith("#"):
            raise MiniYamlError(f"line {index + 1}: trailing content {lines[index]!r}")
        index += 1
    if value is None:
        raise MiniYamlError("empty document")
    return value


# ---------------------------------------------------------------- Solidity


def strip_solidity(text: str) -> str:
    """Remove comments and string literals, preserving length for offsets."""
    out: list[str] = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        two = text[i : i + 2]
        if two == "//":
            while i < n and text[i] != "\n":
                out.append(" ")
                i += 1
        elif two == "/*":
            out.append("  ")
            i += 2
            while i < n and text[i : i + 2] != "*/":
                out.append("\n" if text[i] == "\n" else " ")
                i += 1
            out.append("  ")
            i += 2
        elif ch in "\"'":
            quote = ch
            out.append(" ")
            i += 1
            while i < n and text[i] != quote:
                if text[i] == "\\":
                    out.append(" ")
                    i += 1
                out.append("\n" if text[i] == "\n" else " ")
                i += 1
            out.append(" ")
            i += 1
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def check_solidity() -> None:
    files = sorted(CONTRACTS.rglob("*.sol"))
    if not files:
        fail("no .sol files found")
        return

    for path in files:
        raw = path.read_text(encoding="utf-8")
        rel = path.relative_to(ROOT).as_posix()
        cleaned = strip_solidity(raw)

        # Balanced delimiters.
        for opener, closer in (("{", "}"), ("(", ")"), ("[", "]")):
            depth = 0
            min_depth = 0
            for ch in cleaned:
                if ch == opener:
                    depth += 1
                elif ch == closer:
                    depth -= 1
                    min_depth = min(min_depth, depth)
            if depth != 0:
                fail(f"{rel}: unbalanced {opener}{closer} (final depth {depth})")
            elif min_depth < 0:
                fail(f"{rel}: a {closer} closes before any {opener}")

        if not re.search(r"pragma solidity \^0\.8\.24;", raw):
            fail(f"{rel}: missing `pragma solidity ^0.8.24;`")

        # Every function that declares a named/unnamed return must return.
        for match in re.finditer(r"\bfunction\s+(\w+)\s*\(", cleaned):
            name = match.group(1)
            # Find the parameter list end.
            depth = 0
            i = match.end() - 1
            while i < len(cleaned):
                if cleaned[i] == "(":
                    depth += 1
                elif cleaned[i] == ")":
                    depth -= 1
                    if depth == 0:
                        break
                i += 1
            tail = cleaned[i + 1 :]
            ret = re.match(
                r"\s*(?:external|public|internal|private)?"
                r"(?:\s+(?:view|pure|payable|virtual|override))*"
                r"\s*returns\s*\(",
                tail,
            )
            if not ret:
                continue
            # Locate the body.
            body_start = cleaned.find("{", i + 1)
            if body_start == -1:
                fail(f"{rel}: function {name} has no body")
                continue
            depth = 0
            j = body_start
            while j < len(cleaned):
                if cleaned[j] == "{":
                    depth += 1
                elif cleaned[j] == "}":
                    depth -= 1
                    if depth == 0:
                        break
                j += 1
            body = cleaned[body_start : j + 1]
            # A `returns (T memory x, ...)` tuple in a non-view function is
            # satisfied either by a `return` or by assigning the named variable.
            if re.search(r"\breturn\b", body):
                continue
            names = re.findall(r"returns\s*\(([^)]*)\)", tail)
            if names:
                declared = [
                    part.strip().split()[-1]
                    for part in names[0].split(",")
                    if part.strip()
                ]
                # A named return counts as returned when the body assigns it
                # either directly (`_parse = ...`) or through a member
                # (`config.version = ...`).
                assigned = all(
                    re.search(rf"\b{re.escape(d)}\s*=", body)
                    or re.search(rf"\b{re.escape(d)}\s*\.", body)
                    for d in declared
                )
                if assigned:
                    continue
            fail(f"{rel}: function {name} declares a return value but never returns one")

        note(f"Solidity braces/parens ok: {rel}")

    # The version fixture must agree with the repository VERSION.
    root_version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    contract_version = (CONTRACTS / "VERSION").read_text(encoding="utf-8").strip()
    if root_version != contract_version:
        fail(f"contracts/VERSION ({contract_version}) != VERSION ({root_version})")
    else:
        note(f"contracts/VERSION mirrors VERSION ({root_version})")

    # Deploy config must parse and carry the version.
    config_path = CONTRACTS / "deploy.config.example.json"
    try:
        config = json.loads(config_path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        fail(f"deploy.config.example.json is not valid JSON: {exc}")
    else:
        if config.get("version") != root_version:
            fail(
                "deploy.config.example.json version "
                f"({config.get('version')}) != VERSION ({root_version})"
            )
        else:
            note("deploy.config.example.json parses and matches VERSION")

    # The deploy script must read VERSION rather than restating it.
    deploy = (CONTRACTS / "script" / "Deploy.s.sol").read_text(encoding="utf-8")
    if 'readAndTrim("VERSION")' not in deploy:
        fail("script/Deploy.s.sol does not read the VERSION file")
    if "VersionMismatch" not in deploy:
        fail("script/Deploy.s.sol has no version-mismatch guard")


# ------------------------------------------------------- defect-marker audit


REQUIRED_FIX_MARKERS = {
    "src/GovernanceToken.sol": 3,
    "src/AgentCardAnchor.sol": 3,
    "src/Settlement.sol": 7,
    "src/ReputationRegistry.sol": 6,
}


def check_fix_markers() -> None:
    for rel, minimum in REQUIRED_FIX_MARKERS.items():
        path = CONTRACTS / rel
        text = path.read_text(encoding="utf-8")
        count = text.count("// upstream v2.5.6 fix:")
        if count < minimum:
            fail(f"{rel}: {count} `// upstream v2.5.6 fix:` markers, expected >= {minimum}")
        else:
            note(f"{rel}: {count} upstream-fix markers")


REQUIRED_TESTS = [
    "test_createTask_revertsWhenMsgValueDoesNotEqualReward",
    "test_verifyTask_revertsForNonVerifier",
    "test_disputeTask_revertsForStranger",
    "test_settleTask_cannotReenter",
    "test_acceptTask_revertsForRequester",
    "test_dispute_canSlashExecutor",
    "test_anchor_isFirstWriteWins_andCannotBeOverwritten",
    "test_addVerifier_revertsForNonOwner_andHonoursCap",
    "test_recordReputation_revertsAboveTenThousandBps",
    "test_delegateVotes_actuallyAccumulatesAndMoves",
    "invariant_",
    "testFuzz_",
    "testFuzz_settlementConservesValue",
]


def check_required_tests() -> None:
    tests = "\n".join(
        path.read_text(encoding="utf-8") for path in sorted((CONTRACTS / "test").glob("*.sol"))
    )
    for required in REQUIRED_TESTS:
        if required not in tests:
            fail(f"test suite is missing `{required}`")
        else:
            note(f"test present: {required}")


def main() -> int:
    check_yaml()
    check_solidity()
    check_fix_markers()
    check_required_tests()

    print("== notes ==")
    for line in notes:
        print(f"  ok  {line}")
    if failures:
        print("\n== FAILURES ==")
        for line in failures:
            print(f"  FAIL {line}")
        print(f"\n{len(failures)} check(s) failed")
        return 1
    print(f"\nall {len(notes)} static checks passed")
    print("NOTE: this is not a compile. `forge build` was never run.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
