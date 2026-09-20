"""Live smoke for the Supply Chain Recon ecosystem filter: what the RUNNING
stack stores and serves, as opposed to what the repo says.

Two things the hermetic tests cannot see:
  1. the Postgres column - its default, its type (a plain string, not an array),
     and the values real projects already carry. Rows written by the old
     free-text field can hold "pypi" or "cargo", which the widget renders as an
     empty selection and recon turns into a filter that reports nothing.
  2. the defaults the orchestrator serves a brand-new project form.

Everything self-skips when the stack, the driver or the credentials are absent -
this tier never hard-fails on a missing prerequisite.

Run: python -m pytest tests/test_supply_chain_ecosystems_smoke.py -rs
"""

import json
import os
import re
import unittest
import urllib.error
import urllib.request

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Same catalogue as webapp/src/.../supplyChainEcosystems.ts; the drift guard is
# tests/test_supply_chain_ecosystems_integration.py.
_CATALOGUE = ["npm", "PyPI", "Go", "Maven", "crates.io", "Packagist",
              "RubyGems", "NuGet"]
_CANONICAL_BY_LOWER = {e.lower(): e for e in _CATALOGUE}
_COLUMN = "supply_chain_recon_ecosystems"
_FIELD = "supplyChainReconEcosystems"
_TIMEOUT = 5


def _dotenv(key):
    """A value from the repo .env, without importing dotenv. Never logged."""
    path = os.path.join(_REPO, ".env")
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                name, _, value = line.partition("=")
                if name.strip() == key:
                    return value.strip().strip('"').strip("'")
    except OSError:
        return None
    return None


def _database_url():
    url = os.environ.get("DATABASE_URL") or _dotenv("DATABASE_URL")
    if url:
        return url
    password = _dotenv("POSTGRES_PASSWORD")
    if not password:
        return None
    user = os.environ.get("POSTGRES_USER") or _dotenv("POSTGRES_USER") or "whitehat"
    db = os.environ.get("POSTGRES_DB") or _dotenv("POSTGRES_DB") or "whitehat"
    # `postgres` inside the compose network, loopback from the host.
    host = os.environ.get("POSTGRES_HOST", "postgres")
    return "postgresql://{}:{}@{}:5432/{}".format(user, password, host, db)


def _connect():
    """A live connection, or None with the reason to skip."""
    try:
        import psycopg
    except ImportError:
        return None, "psycopg not installed in this image"
    url = _database_url()
    if not url:
        return None, "no DATABASE_URL / POSTGRES_PASSWORD available"
    try:
        return psycopg.connect(url, connect_timeout=_TIMEOUT), None
    except Exception as exc:  # driver raises many types; all mean "no stack"
        return None, "postgres unreachable ({})".format(type(exc).__name__)


def _tokens(value):
    return [t.strip() for t in (value or "").split(",") if t.strip()]


class TestStoredColumn(unittest.TestCase):
    conn = None
    skip_reason = None

    @classmethod
    def setUpClass(cls):
        cls.conn, cls.skip_reason = _connect()

    @classmethod
    def tearDownClass(cls):
        if cls.conn is not None:
            cls.conn.close()

    def setUp(self):
        if self.conn is None:
            self.skipTest(self.skip_reason)

    def _column_row(self):
        with self.conn.cursor() as cur:
            cur.execute(
                "SELECT data_type, column_default FROM information_schema.columns "
                "WHERE table_name = 'projects' AND column_name = %s", (_COLUMN,))
            return cur.fetchone()

    def test_the_column_exists(self):
        self.assertIsNotNone(self._column_row(),
                             "projects.{} is missing - has prisma db push run "
                             "since the schema change?".format(_COLUMN))

    def test_the_column_is_a_scalar_string_not_an_array(self):
        # The widget serializes to a comma-separated string and recon splits on
        # ",". An ARRAY column would make both wrong at once.
        row = self._column_row()
        if row is None:
            self.skipTest("column absent (covered by the test above)")
        self.assertNotEqual(row[0], "ARRAY")

    def test_the_column_default_is_canonical(self):
        row = self._column_row()
        if row is None or not row[1]:
            self.skipTest("column or default absent")
        # Postgres renders it as 'npm'::text
        literal = re.match(r"^'(.*)'::", row[1])
        value = literal.group(1) if literal else row[1]
        for token in _tokens(value):
            self.assertIn(token, _CATALOGUE,
                          "column default {!r} is not selectable in the UI".format(value))

    def test_every_stored_project_value_is_selectable_and_canonical(self):
        with self.conn.cursor() as cur:
            cur.execute("SELECT DISTINCT {} FROM projects".format(_COLUMN))
            values = [row[0] for row in cur.fetchall()]
        if not values:
            self.skipTest("no projects in this database")
        bad = []
        for value in values:
            for token in _tokens(value):
                if token not in _CATALOGUE:
                    hint = _CANONICAL_BY_LOWER.get(token.lower())
                    bad.append("{!r}{}".format(
                        token, " (should be {!r})".format(hint) if hint else ""))
        self.assertEqual(bad, [],
                         "stored ecosystem values recon can never match: {}. "
                         "Re-tick the ecosystems in the project form to "
                         "canonicalize them.".format(", ".join(bad)))

    def test_no_project_stores_a_whitespace_only_value(self):
        # Used to mean "report nothing"; now means "no filter". Either way it is
        # a value no UI path can produce, so it should not exist.
        with self.conn.cursor() as cur:
            cur.execute(
                "SELECT COUNT(*) FROM projects WHERE {0} <> '' AND btrim({0}) = ''"
                .format(_COLUMN))
            self.assertEqual(cur.fetchone()[0], 0)


def _fetch_orchestrator_defaults():
    """(payload, skip_reason). Any non-200 counts as 'stack not usable'."""
    key = os.environ.get("ORCHESTRATOR_API_KEY") or _dotenv("ORCHESTRATOR_API_KEY")
    bases = [os.environ.get("RECON_ORCHESTRATOR_URL"),
             "http://recon-orchestrator:8010", "http://localhost:8010"]
    last = "no orchestrator candidate answered"
    for base in [b for b in bases if b]:
        url = base.rstrip("/") + "/defaults"
        req = urllib.request.Request(url)
        if key:
            req.add_header("X-Orchestrator-Key", key)
        try:
            with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
                return json.loads(resp.read().decode("utf-8")), None
        except urllib.error.HTTPError as exc:
            last = "{} -> HTTP {}".format(url, exc.code)
        except (urllib.error.URLError, OSError, ValueError, TimeoutError) as exc:
            last = "{} -> {}".format(url, type(exc).__name__)
    return None, last


class TestServedDefaults(unittest.TestCase):
    defaults = None
    skip_reason = None

    @classmethod
    def setUpClass(cls):
        cls.defaults, cls.skip_reason = _fetch_orchestrator_defaults()

    def setUp(self):
        if self.defaults is None:
            self.skipTest("orchestrator /defaults unusable: {}".format(self.skip_reason))

    def test_the_field_survives_the_snake_to_camel_conversion(self):
        # SUPPLY_CHAIN_RECON_ECOSYSTEMS -> supplyChainReconEcosystems. If the
        # converter or RUNTIME_ONLY_KEYS drops it, a new project form falls back
        # to its own default and the two silently diverge.
        self.assertIn(_FIELD, self.defaults)

    def test_the_served_default_is_canonical_and_harvestable(self):
        value = self.defaults.get(_FIELD)
        self.assertIsInstance(value, str)
        tokens = _tokens(value)
        self.assertTrue(tokens, "served default selects no ecosystem at all")
        for token in tokens:
            self.assertIn(token, _CATALOGUE)
        self.assertIn("npm", tokens,
                      "a fresh project would harvest npm packages and then "
                      "filter every one of them away")


if __name__ == "__main__":
    unittest.main()
