"""The ``nau_sdk`` test suite.

Run it with ::

    <python> sdks/python/run_tests.py

This package marker exists so that ``unittest discover`` can walk the directory
and so that ``from _support import ...`` resolves.  Third-party test runner
configuration (``pytest``) is deliberately absent: the suite must run with the
standard library alone.
"""
