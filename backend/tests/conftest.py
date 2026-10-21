"""Test configuration: no network, no shared database.

Environment is set before any test module imports the app, so the app neither bootstraps
(which would download the Tranco list) nor touches the developer's real phishing.db.
"""
import os
import tempfile

os.environ.setdefault("PG_NO_BOOTSTRAP", "1")
os.environ.setdefault("PG_DB", os.path.join(tempfile.mkdtemp(prefix="pg-tests-"), "test.db"))
