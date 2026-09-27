"""Run the ``nau_sdk`` test suite with the standard library only.

Usage (from the repository root)::

    <python> sdks/python/run_tests.py

Exits ``0`` when everything passes and non-zero on any failure or error.  No
third-party test runner is required -- ``pytest`` is deliberately not a
dependency of this SDK.
"""

from __future__ import annotations

import os
import sys
import unittest


def main(argv: "list[str] | None" = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    here = os.path.dirname(os.path.abspath(__file__))
    tests_dir = os.path.join(here, "tests")

    # Make `import nau_sdk` work without an install step.
    if here not in sys.path:
        sys.path.insert(0, here)

    verbosity = 2 if "-q" not in argv else 1
    argv = [a for a in argv if a not in ("-q", "-v")]

    loader = unittest.TestLoader()
    suite = loader.discover(start_dir=tests_dir, top_level_dir=here)
    if loader.errors:
        for error in loader.errors:
            print(error, file=sys.stderr)
        return 2

    total = suite.countTestCases()
    print(f"nau_sdk: discovered {total} tests in {tests_dir}")
    if total == 0:
        print("error: no tests were discovered", file=sys.stderr)
        return 2

    runner = unittest.TextTestRunner(verbosity=verbosity, buffer=False)
    result = runner.run(suite)

    print(
        f"nau_sdk: ran {result.testsRun} tests, "
        f"{len(result.failures)} failures, {len(result.errors)}, "
        f"{len(result.skipped)} skipped"
    )
    if result.skipped:
        # A skipped test is a test that did not run. Upstream hid 11 crypto tests
        # behind a module-level skipif; nothing here may ever be skipped.
        for test, reason in result.skipped:
            print(f"error: {test} was SKIPPED ({reason})", file=sys.stderr)
        return 3
    if not result.wasSuccessful():
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
