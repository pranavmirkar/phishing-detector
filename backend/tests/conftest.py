"""Test configuration: no network, no shared database.

Environment is set before any test module imports the app, so the app neither bootstraps
(which would download the Tranco list) nor touches the developer's real phishing.db.
"""
import os
import tempfile

os.environ.setdefault("PG_NO_BOOTSTRAP", "1")
os.environ.setdefault("PG_MODEL", "off")        # unit tests exercise the rule engine; the model has its own tests
_tmp = tempfile.mkdtemp(prefix="pg-tests-")
os.environ.setdefault("PG_DB", os.path.join(_tmp, "test.db"))
os.environ.setdefault("PG_BENCH_DATA", os.path.join(_tmp, "bench-data"))     # tests never touch real downloaded corpora
os.environ.setdefault("PG_BENCH_RUNS", os.path.join(_tmp, "bench-runs"))
