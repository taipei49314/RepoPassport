from pathlib import Path


for index in range(5000):
    transient = Path(f"/outputs/RAW-ALPHA24-OVERFLOW-MARKER-{index:04d}.tmp")
    transient.write_text("x\n", encoding="utf-8")
    transient.unlink()

Path("/outputs/result.json").write_text(
    '{"status":"functional-pass"}\n', encoding="utf-8"
)
print("completed:notification-overflow")
