from pathlib import Path
import sys


baseline = Path("/outputs/baseline.json")

if sys.argv[1:] == ["setup"]:
    baseline.write_text(
        '{"state":"RAW-ALPHA24-RESTORE-CONTENT-MARKER"}\n', encoding="utf-8"
    )
elif sys.argv[1:] == ["exercise"]:
    original = baseline.read_text(encoding="utf-8")
    baseline.write_text('{"state":"temporary-mutation"}\n', encoding="utf-8")
    baseline.write_text(original, encoding="utf-8")
    Path("/outputs/result.json").write_text(
        '{"status":"functional-pass"}\n', encoding="utf-8"
    )
    print("completed:write-restore")
else:
    raise SystemExit("usage: fixture.py <setup|exercise>")
