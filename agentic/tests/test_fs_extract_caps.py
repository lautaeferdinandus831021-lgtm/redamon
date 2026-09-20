#!/usr/bin/env python3
"""D10 — fs_extract zip/tar/gz decompression caps.

Verifies a normal small archive extracts, and that an over-entry-count, an
over-declared-size, and an over-stream (gz) archive are aborted BEFORE inflating.

Run in the agent image: python3 tests/test_fs_extract_caps.py
"""
import asyncio
import gzip
import io
import os
import sys
import tarfile
import tempfile
import zipfile
import zlib
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

TMP = tempfile.mkdtemp(prefix="fsextract-")
os.environ["WORKSPACE_ROOT"] = TMP
os.environ["WHITEHAT_PROJECT_ID"] = "p1"
# small caps so we don't need giant fixtures
os.environ["FS_EXTRACT_MAX_ENTRIES"] = "5"
os.environ["FS_EXTRACT_MAX_TOTAL_BYTES"] = "1024"  # 1 KB

import workspace_fs as fs  # noqa: E402
from agent_context import current_project_id  # noqa: E402

current_project_id.set("p1")
WS = fs._workspace_root_for("p1")
WS.mkdir(parents=True, exist_ok=True)

PASS = 0
FAIL = 0


def check(desc, cond):
    global PASS, FAIL
    if cond:
        PASS += 1; print(f"  PASS {desc}")
    else:
        FAIL += 1; print(f"  FAIL {desc}")


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def main():
    # 1. normal small zip extracts
    z = WS / "ok.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("a.txt", "hello")
        zf.writestr("b.txt", "world")
    res = _run(fs.fs_extract("ok.zip", "out_ok"))
    check("normal zip extracts", "Extracted 2 entries" in res)

    # 2. too many entries -> aborted
    z2 = WS / "many.zip"
    with zipfile.ZipFile(z2, "w") as zf:
        for i in range(10):
            zf.writestr(f"f{i}.txt", "x")
    res = _run(fs.fs_extract("many.zip", "out_many"))
    check("over-entry-count zip aborted", "too many entries" in res)

    # 3. over declared uncompressed size -> aborted (2 KB > 1 KB cap)
    z3 = WS / "big.zip"
    with zipfile.ZipFile(z3, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("big.txt", "A" * 2048)
    res = _run(fs.fs_extract("big.zip", "out_big"))
    check("over-size zip aborted before inflation", "decompresses too large" in res)

    # 4. tar bomb (declared size) -> aborted
    t = WS / "big.tar"
    with tarfile.open(t, "w") as tf:
        data = b"B" * 4096
        info = tarfile.TarInfo("big.bin")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    res = _run(fs.fs_extract("big.tar", "out_tar"))
    check("over-size tar aborted", "decompresses too large" in res)

    # 5. gz stream over the byte ceiling -> aborted, partial output removed
    g = WS / "big.gz"
    with gzip.open(g, "wb") as gz:
        gz.write(b"C" * 4096)
    res = _run(fs.fs_extract("big.gz", "out_gz"))
    check("over-size gz stream aborted", "exceeds max size" in res)
    check("gz partial output cleaned up", not (WS / "out_gz" / "big").exists())

    print()
    print(f"RESULT: PASS={PASS} FAIL={FAIL}")
    return 0 if FAIL == 0 else 1


def test_fs_extract_caps():
    """pytest entrypoint: run the script-style checks; main() returns
    non-zero on any failed check (bucket-1 runner-compat conversion)."""
    assert main() == 0


if __name__ == "__main__":
    sys.exit(main())
