#!/usr/bin/env python3
"""Cross-check every contract API call in `test/` and `script/` against the API the
contracts actually declare.

A real compiler would catch this class of error, but no Solidity compiler and no
Foundry exist in the environment this tree was written in. So this script does the
name-and-arity half mechanically:

  * it indexes every contract in `src/`, `test/` and `script/` for its declared
    public surface (functions, public and public-immutable state variables,
    public mappings, struct/enum/event/error names);
  * it infers the contract type of each local variable and state variable from its
    declaration;
  * it resolves `variable.member(...)` call sites against that type, reporting an
    unknown member or a call made with the wrong number of arguments.

Exit code 0 means "every resolved call site names a declared member with matching
arity". It does NOT mean the code compiles: types, overloads, mutability, struct
literals and inheritance resolution are all outside its scope.
"""

from __future__ import annotations

import pathlib
import re
import sys

sys.dont_write_bytecode = True

ROOT = pathlib.Path(__file__).resolve().parents[1]
CONTRACTS = ROOT / "contracts"

failures: list[str] = []
INDEX: dict[str, set[str]] = {}
ARITY: dict[tuple[str, str], int] = {}
BASES: dict[str, list[str]] = {}


# --------------------------------------------------------------------- lexing


def strip_comments(text: str) -> str:
    """Blank out comments and string literals, preserving offsets."""
    out: list[str] = []
    i = 0
    n = len(text)
    while i < n:
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
        elif text[i] in "\"'":
            quote = text[i]
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
            out.append(text[i])
            i += 1
    return "".join(out)


def arg_count(text: str, open_paren: int) -> tuple[int, int]:
    """(arguments, index of matching close paren) for the '(' at open_paren."""
    depth = 0
    index = open_paren
    arity = 0
    saw_any = False
    while index < len(text):
        ch = text[index]
        if ch == "(":
            depth += 1
            if depth == 1:
                index += 1
                continue
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return (arity + 1 if saw_any else 0), index
        elif ch == "," and depth == 1:
            arity += 1
        if depth >= 1 and not ch.isspace() and ch not in "(),":
            saw_any = True
        index += 1
    raise ValueError("unbalanced parentheses")


# ------------------------------------------------------------------- indexing


def index_contract(name: str, body: str) -> None:
    members: set[str] = set()
    for match in re.finditer(r"\bfunction\s+(\w+)\s*\(", body):
        member = match.group(1)
        members.add(member)
        arity, _ = arg_count(body, match.end() - 1)
        ARITY[(name, member)] = arity
    for match in re.finditer(r"\b(?:event|error|struct|modifier|enum)\s+(\w+)", body):
        members.add(match.group(1))
    for match in re.finditer(r"\bpublic\s+(?:constant\s+)?(\w+)\s*(?:\[[^\]]*\])?\s*[;=]", body):
        members.add(match.group(1))
    for match in re.finditer(r"\bpublic\s+immutable\s+(\w+)\s*;", body):
        members.add(match.group(1))
    for match in re.finditer(r"\bmapping\s*\([^;]*?\)\s*public\s+(\w+)\s*;", body):
        members.add(match.group(1))
    # Enum members are reached through the enum name (`Status.Open`).
    for match in re.finditer(r"\benum\s+(\w+)\s*\{([^}]*)\}", body):
        for constant in match.group(2).split(","):
            constant = constant.strip()
            if constant:
                members.add(constant)
    # Struct field names are reached through a struct value, not the contract;
    # indexing them is harmless and avoids false positives.
    for match in re.finditer(r"\bstruct\s+\w+\s*\{([^}]*)\}", body):
        for field in re.finditer(r"[;,{]\s*[\w\[\]\(\)\s]*?\b(\w+)\s*;", match.group(1)):
            members.add(field.group(1))
    INDEX.setdefault(name, set()).update(members)


def index_file(path: pathlib.Path) -> None:
    text = strip_comments(path.read_text(encoding="utf-8"))
    for match in re.finditer(r"\b(?:abstract\s+)?contract\s+(\w+)", text):
        name = match.group(1)
        # Direct base contracts, from the `is A, B` list. Without this the
        # inherited surface (`Ownable.owner`, `ERC20.transfer`) looks undeclared.
        bases: list[str] = []
        head = text[match.end() : text.find("{", match.end())]
        is_match = re.search(r"\bis\b(.*)", head, re.DOTALL)
        if is_match:
            for part in is_match.group(1).split(","):
                base = re.match(r"\s*([A-Z]\w*)", part)
                if base:
                    bases.append(base.group(1))
        BASES[name] = bases

        # Body of this contract: from the opening brace to its match.
        brace = text.find("{", match.end())
        if brace == -1:
            continue
        depth = 0
        index = brace
        while index < len(text):
            if text[index] == "{":
                depth += 1
            elif text[index] == "}":
                depth -= 1
                if depth == 0:
                    break
            index += 1
        index_contract(name, text[brace : index + 1])
    # `library` blocks are not expected here, but index them the same way.
    for match in re.finditer(r"\blibrary\s+(\w+)", text):
        index_contract(match.group(1), text)


def resolve_bases() -> None:
    """Fold inherited members into each contract's surface, transitively."""
    for _ in range(8):  # deep enough for any hierarchy in this tree
        changed = False
        for name, bases in BASES.items():
            target = INDEX.setdefault(name, set())
            before = len(target)
            for base in bases:
                target |= INDEX.get(base, set())
                for (owner, member), arity in list(ARITY.items()):
                    if owner == base and (name, member) not in ARITY:
                        ARITY[(name, member)] = arity
            if len(target) != before:
                changed = True
        if not changed:
            break


# -------------------------------------------------------- type inference


TYPE_DECL = re.compile(
    r"\b([A-Z]\w*)\s+(?:(?:public|private|internal|external|constant|immutable|memory|storage|calldata)\s+)*(\w+)\s*(?:=|;|,|\))"
)


def infer_types(text: str) -> dict[str, str]:
    """Map variable name -> contract type for `Contract x;` / `Contract x = ...`."""
    types: dict[str, str] = {}
    for match in re.finditer(
        r"\b([A-Z]\w*)\s+"
        r"(?:(?:public|private|internal|constant|immutable)\s+)*"
        r"([a-z]\w*)\s*(?:=|;|,|\))",
        text,
    ):
        contract, variable = match.group(1), match.group(2)
        if contract in INDEX or contract in {
            "Settlement",
            "GovernanceToken",
            "AgentCardAnchor",
            "ReputationRegistry",
        }:
            types.setdefault(variable, contract)
    # Function parameters: `function f(Settlement s, ...)`.
    for match in re.finditer(r"function\s+\w+\s*\(([^)]*)\)", text):
        for param in match.group(1).split(","):
            bits = [b for b in param.split() if b not in ("memory", "calldata", "storage")]
            if len(bits) >= 2 and bits[0][:1].isupper():
                types.setdefault(bits[-1].lstrip("_"), bits[0])
    # Constructor parameters and struct-literal-free initialisers.
    for match in re.finditer(r"\bnew\s+([A-Z]\w*)\s*\(", text):
        pass  # handled by the variable declaration on the same line
    return types


def check_file(path: pathlib.Path) -> int:
    rel = path.relative_to(ROOT).as_posix()
    raw = path.read_text(encoding="utf-8")
    text = strip_comments(raw)
    types = infer_types(text)
    checked = 0
    for match in re.finditer(r"\b([a-z]\w*)\.(\w+)\s*(?:\{[^}]*\})?\s*\(", text):
        variable, member = match.group(1), match.group(2)
        contract = types.get(variable)
        if contract is None or contract not in INDEX:
            continue
        checked += 1
        # `token.delegate(alice)` parses as `token.delegate(`; the `{...}` form is
        # `settlement.createTask{value: x}(...)`.
        open_paren = match.end() - 1
        arity, _ = arg_count(text, open_paren)
        lineno = text[: match.start()].count("\n") + 1
        if member not in INDEX[contract]:
            failures.append(f"{rel}:{lineno}: `{variable}.{member}` -> {contract} has no member {member}")
            continue
        declared = ARITY.get((contract, member))
        if declared is not None and declared != arity:
            failures.append(
                f"{rel}:{lineno}: `{variable}.{member}` ({contract}) called with {arity} args, "
                f"declared with {declared}"
            )
    return checked


def main() -> int:
    for path in sorted(CONTRACTS.rglob("*.sol")):
        index_file(path)
    resolve_bases()

    total = 0
    for path in sorted(
        list((CONTRACTS / "test").rglob("*.sol")) + list((CONTRACTS / "script").rglob("*.sol"))
    ):
        total += check_file(path)

    print(f"indexed {len(INDEX)} contracts: {', '.join(sorted(INDEX))}")
    print(f"resolved {total} contract-typed call sites in test/ and script/")
    if failures:
        print("\n== FAILURES ==")
        for line in failures:
            print(f"  FAIL {line}")
        return 1
    print("every resolved call site names a declared member with matching arity")
    print("NOTE: this is not a compile. `forge build` was never run.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
