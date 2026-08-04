from pathlib import Path
import sys


build_only = Path("/outputs/build-only.json")

if sys.argv[1:] == ["build"]:
    build_only.write_text('{"state":"build-declared"}\n', encoding="utf-8")
elif sys.argv[1:] == ["exercise"]:
    build_only.write_text(
        '{"state":"RAW-ALPHA24-WRONG-PHASE-PATH-MARKER"}\n', encoding="utf-8"
    )
    Path("/outputs/result.json").write_text(
        '{"status":"functional-pass"}\n', encoding="utf-8"
    )
    print("completed:wrong-phase")
else:
    raise SystemExit("usage: fixture.py <build|exercise>")
