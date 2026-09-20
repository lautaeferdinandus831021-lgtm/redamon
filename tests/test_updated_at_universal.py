"""Every node write must stamp `updated_at`.

The graph tables all carry an "Updated" column and land sorted newest-first, so
a write that does not stamp the node renders as a blank cell and sorts to the
bottom for ever. That failure is invisible at write time: the scan succeeds, the
node is there, only the timestamp is missing.

It is also the DEFAULT outcome for a new write - forgetting a line is easier
than remembering one - so this is a static sweep rather than a behavioural test.
It parses every Cypher literal in the graph writers and fails on any node
MERGE/CREATE whose variable never gets `updated_at` assigned in the same query.

Deterministic and hermetic: pure AST + regex over the source, no Neo4j needed.

Run:
    python3 -m unittest tests.test_updated_at_universal
"""
import ast
import os
import re
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Every tree that persists to the graph.
#
# `recon/` is NOT optional and was originally left out on the assumption that
# the pipeline hands everything to a graph_db mixin. It does not: the
# partial-recon modules write their own Cypher, and 21 node writes there were
# missing the stamp while this sweep reported the repo clean. If a new tree
# starts writing Cypher, add it here or it is unguarded.
ROOTS = ("graph_db", "scanners", "agentic", "recon", "recon_orchestrator",
         "services", "mcp")

# Bookkeeping marker for the schema migrations, never rendered as an entity and
# deliberately exempt - it records WHEN it was applied via `applied_at`.
EXEMPT_LABELS = frozenset({"WhiteHatSchemaMigration"})

NODE_WRITE = re.compile(r'(?:MERGE|CREATE)\s*\(\s*(\w+)\s*:\s*(\w+)')


def _cypher_literals(tree):
    """Every string that is run as Cypher: inline `.run(...)` arguments, plus
    `cypher = "..."` locals - the attack-chain writer builds its query into one
    first, so a call-site-only sweep would skip every ChainStep write."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if (isinstance(func, ast.Attribute)
                    and func.attr in ("run", "execute_query")
                    and node.args
                    and isinstance(node.args[0], ast.Constant)
                    and isinstance(node.args[0].value, str)):
                yield node.args[0].value
        elif isinstance(node, ast.Assign):
            names = [t.id for t in node.targets if isinstance(t, ast.Name)]
            if any(re.fullmatch(r"(cypher|query|q|.*_cypher|.*_query)", n) for n in names):
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    yield node.value.value


def _python_files():
    for root in ROOTS:
        base = os.path.join(REPO, root)
        if not os.path.isdir(base):
            continue
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = [d for d in dirnames if d not in ("__pycache__", "tests")]
            for name in filenames:
                if name.endswith(".py") and "test" not in name:
                    yield os.path.join(dirpath, name)


def find_unstamped():
    """(relative path, variable, label) for every node write missing the stamp."""
    gaps = []
    for path in _python_files():
        try:
            with open(path, encoding="utf-8") as fh:
                tree = ast.parse(fh.read())
        except (SyntaxError, UnicodeDecodeError):
            continue
        for query in _cypher_literals(tree):
            if "MERGE (" not in query and "CREATE (" not in query:
                continue
            for match in NODE_WRITE.finditer(query):
                var, label = match.group(1), match.group(2)
                if label in EXEMPT_LABELS:
                    continue
                if re.search(r"\b%s\.updated_at\s*=" % re.escape(var), query):
                    continue
                gaps.append((os.path.relpath(path, REPO), var, label))
    return gaps


class TestUpdatedAtIsUniversal(unittest.TestCase):

    def test_every_node_write_stamps_updated_at(self):
        gaps = find_unstamped()
        if gaps:
            lines = "\n".join(
                "  %s  ->  MERGE (%s:%s)" % (path, var, label)
                for path, var, label in sorted(set(gaps))
            )
            self.fail(
                "%d node write(s) do not set `updated_at`, so the Updated column "
                "in every graph table will be blank for them:\n%s\n\n"
                "Add `SET <var>.updated_at = datetime()` to the query. Use a plain "
                "SET, not ON CREATE SET: the column means 'last written', so it "
                "has to move when an existing node is re-merged." % (len(gaps), lines)
            )

    def test_the_sweep_actually_finds_writes(self):
        """A rename or a moved directory would otherwise make the test above
        pass by scanning nothing at all."""
        seen = 0
        for path in _python_files():
            try:
                with open(path, encoding="utf-8") as fh:
                    tree = ast.parse(fh.read())
            except (SyntaxError, UnicodeDecodeError):
                continue
            for query in _cypher_literals(tree):
                seen += len(NODE_WRITE.findall(query))
        self.assertGreater(
            seen, 150,
            "only %d node writes found; the sweep is probably looking in the "
            "wrong place" % seen,
        )

    def test_detector_catches_a_missing_stamp(self):
        """The detector must actually be able to fail."""
        tree = ast.parse(
            'session.run("MERGE (p:Port {number: $n}) SET p.state = \'open\'")'
        )
        queries = list(_cypher_literals(tree))
        self.assertEqual(len(queries), 1)
        var, label = NODE_WRITE.search(queries[0]).groups()
        self.assertFalse(re.search(r"\b%s\.updated_at\s*=" % var, queries[0]))

    def test_detector_accepts_a_stamped_write(self):
        tree = ast.parse(
            'session.run("MERGE (p:Port {number: $n}) SET p.updated_at = datetime()")'
        )
        query = list(_cypher_literals(tree))[0]
        var, _label = NODE_WRITE.search(query).groups()
        self.assertTrue(re.search(r"\b%s\.updated_at\s*=" % var, query))


if __name__ == "__main__":
    unittest.main()
