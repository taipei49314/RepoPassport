from pathlib import Path


transient = Path("/outputs/RAW-ALPHA24-TRANSIENT-PATH-MARKER.tmp")
transient.write_text("RAW-ALPHA24-TRANSIENT-CONTENT-MARKER\n", encoding="utf-8")
transient.unlink()
Path("/outputs/result.json").write_text(
    '{"status":"functional-pass"}\n', encoding="utf-8"
)
print("completed:transient-create-delete")
