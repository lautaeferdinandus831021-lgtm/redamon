#!/usr/bin/env python3
"""
Regenerate the resolved-settings golden master baselines.

Deliberately NOT a test and never called from one. A baseline that a test run
can rewrite is not a baseline: the first refactor that changes behaviour would
quietly update the file it was supposed to fail against.

Run it only when a settings change is intended, and read the diff:

    docker run --rm -u "$(id -u):$(id -g)" -v "$PWD:/repo" -w /repo/recon \\
      -e PYTHONPATH=/repo:/repo/recon -e HOME=/tmp --entrypoint sh whitehat-recon \\
      -c 'python /repo/recon/tests/regen_golden_settings.py'
    git diff recon/tests/fixtures/golden_settings/

`-u` is not optional. Without it the container writes the baselines as root and
the host cannot rewrite or even `git checkout` them afterwards.

Every line of that diff is a value some scan will now run with.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_REPO = _HERE.parents[1]
for p in (str(_REPO), str(_REPO / "recon")):
    if p not in sys.path:
        sys.path.insert(0, p)

from recon.tests.golden_settings import FIXTURE_DIR, cases  # noqa: E402
from recon.tests.golden_settings_runner import resolve  # noqa: E402


def main() -> int:
    FIXTURE_DIR.mkdir(parents=True, exist_ok=True)
    written = 0
    for name, row in cases().items():
        resolved = resolve(row)
        path = FIXTURE_DIR / f"{name}.json"
        text = json.dumps(resolved, indent=1, sort_keys=True, default=str) + "\n"
        if not path.exists() or path.read_text(encoding="utf-8") != text:
            path.write_text(text, encoding="utf-8")
            written += 1
        print(f"  {name}: {len(resolved)} keys")
    print(f"\n{written} baseline(s) changed. Read `git diff {FIXTURE_DIR.relative_to(_REPO)}`.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
