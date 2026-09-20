"""`graph_db/schema.py` builds its constraints from the label-key declaration.

Before this, a node label was declared twice: once as a `CREATE CONSTRAINT`
string in schema.py, and once as prose in the text-to-cypher prompt. Adding a
label meant editing both, and forgetting either failed silently - no error, just
a label the agent could never query, or a MERGE with no uniqueness guarantee
behind it.

Now `graph_db/schema_keys.py` is the single declaration and schema.py renders
its statements from it. This file pins the two things that makes safe:

1. The generated statements are BYTE-IDENTICAL to the 45 originals. The
   constraint name is part of the identity - a same-name `CREATE ... IF NOT
   EXISTS` against a database still holding the old constraint is a silent
   no-op - so a reworded statement is a schema migration, not a refactor.

2. Every tenant-scoped key still ends in user_id + project_id. That tuple is the
   tenant isolation boundary, not a convention: dropping it from a key would let
   two projects collide on one node.

Run:
    docker run --rm --entrypoint python3 -v "$PWD:/work:ro" -w /work \\
        whitehat-recon:latest recon/tests/test_schema_constraints_generated.py
"""
from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
KEYS_PY = PROJECT_ROOT / "graph_db" / "schema_keys.py"
FROZEN = PROJECT_ROOT / "recon" / "tests" / "fixtures" / "constraints_frozen.json"
CATALOG_PY = PROJECT_ROOT / "graph_db" / "schema_catalog.py"


def _load(path: Path, name: str):
    """By path: graph_db/__init__ imports the neo4j driver these tests do not need."""
    sys.path.insert(0, str(path.parent))
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


keys = _load(KEYS_PY, "schema_keys")


def build_constraints(decl) -> list[str]:
    """Mirror of schema.build_constraints, so this test does not need neo4j."""
    out = []
    for k in decl:
        joined = ", ".join(f"{k['var']}.{p}" for p in k["key_properties"])
        inner = f"({joined})" if len(k["key_properties"]) > 1 else joined
        out.append(
            f"CREATE CONSTRAINT {k['constraint']} IF NOT EXISTS "
            f"FOR ({k['var']}:{k['label']}) REQUIRE {inner} IS UNIQUE"
        )
    return out


def test_generated_constraints_are_byte_identical_to_the_originals():
    frozen = json.loads(FROZEN.read_text(encoding="utf-8"))
    generated = build_constraints(keys.KEY_CONSTRAINTS)
    assert generated == frozen, (
        "the generated constraints differ from the frozen originals. This is a "
        "database migration, not a refactor: a renamed constraint needs a DROP in "
        "DROP_LEGACY_CONSTRAINTS, because a same-name CREATE IF NOT EXISTS against "
        "an existing constraint is a silent no-op.\\n"
        + "\\n".join(
            f"  frozen : {f}\\n  gen    : {g}"
            for f, g in zip(frozen, generated)
            if f != g
        )
    )


def test_schema_py_no_longer_hardcodes_constraint_statements():
    """The point of the inversion. A second list here is a second source."""
    src = (PROJECT_ROOT / "graph_db" / "schema.py").read_text(encoding="utf-8")
    # Exclude build_constraints() itself: it necessarily contains the literal it
    # generates, and matching that would make this test catch its own fix.
    body = re.sub(r"def build_constraints\(.*?\n\n", "", src, flags=re.S)
    assert '"CREATE CONSTRAINT' not in body, (
        "hardcoded CREATE CONSTRAINT strings are back in schema.py; they must be "
        "declared once in schema_keys.py and rendered by build_constraints()"
    )
    assert "from graph_db.schema_keys import KEY_CONSTRAINTS" in src


def test_every_composite_natural_key_carries_both_tenant_columns():
    """The isolation boundary, for the keys that need it.

    A COMPOSITE key is built from natural attributes - a domain name, a port
    number - which repeat across projects, so it must include the tenant tuple
    or two projects collide on one node.

    A single-property key is an opaque generated id (chain_id, step_id,
    chunk_id) that is already unique on its own. Those nodes still carry
    user_id/project_id for the tenant filter; they simply do not need them in
    the uniqueness key, and requiring it would be cargo-culting the rule rather
    than applying it.
    """
    globals_ = {"CVE", "MitreData", "Capec"}
    bad = [
        k["label"]
        for k in keys.KEY_CONSTRAINTS
        if k["label"] not in globals_
        and len(k["key_properties"]) > 1
        and not {"user_id", "project_id"} <= set(k["key_properties"])
    ]
    assert not bad, (
        f"composite keys built from natural attributes but missing the tenant "
        f"tuple: {', '.join(bad)}"
    )


def test_single_property_keys_are_opaque_ids_not_natural_attributes():
    """The other half of the rule above: a single-property key is only safe if
    that property is a generated id. Keying on a bare `name` would silently
    merge two projects' nodes."""
    suspicious = [
        f"{k['label']}.{k['key_properties'][0]}"
        for k in keys.KEY_CONSTRAINTS
        if len(k["key_properties"]) == 1
        and not k["key_properties"][0].endswith("_id")
        and k["key_properties"][0] != "id"
    ]
    assert not suspicious, (
        f"single-property keys that are not an id: {', '.join(suspicious)}. "
        "Either add the tenant tuple or key on a generated id."
    )


def test_the_catalog_reexports_the_same_declaration():
    """One declaration, several readers. A reader is not a duplicate; a second
    list would be."""
    catalog = _load(CATALOG_PY, "schema_catalog")
    assert catalog.KEY_CONSTRAINTS is keys.KEY_CONSTRAINTS or (
        catalog.KEY_CONSTRAINTS == keys.KEY_CONSTRAINTS
    )
    assert catalog.LABELS_WITH_KEYS == keys.LABELS_WITH_KEYS


def test_constraint_names_are_unique():
    """Two labels sharing a constraint name means the second silently no-ops."""
    names = [k["constraint"] for k in keys.KEY_CONSTRAINTS]
    dupes = {n for n in names if names.count(n) > 1}
    assert not dupes, f"duplicate constraint names: {', '.join(sorted(dupes))}"


if __name__ == "__main__":
    passed, failures = 0, []
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"  PASS  {name}")
                passed += 1
            except AssertionError as exc:
                print(f"  FAIL  {name}: {exc}")
                failures.append(name)
            except Exception as exc:  # noqa: BLE001
                print(f"  ERROR {name}: {type(exc).__name__}: {exc}")
                failures.append(name)
    print()
    print(f"{passed} passed, {len(failures)} failed")
    sys.exit(1 if failures else 0)
