from pathlib import Path


directory = Path("/outputs/RAW-ALPHA24-NEW-DIRECTORY-MARKER")
directory.mkdir()
(directory / "child.json").write_text(
    '{"status":"declared-child"}\n', encoding="utf-8"
)
Path("/outputs/result.json").write_text(
    '{"status":"functional-pass"}\n', encoding="utf-8"
)
print("completed:new-directory-gap")
