import json
import pathlib
import sys


def seed(input_path: str, state_path: str) -> None:
    message = pathlib.Path(input_path).read_text(encoding="utf-8").strip()
    destination = pathlib.Path(state_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps({"message": message, "runtime": "python"}, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"seeded:{message}")


def process(state_path: str, output_path: str) -> None:
    state = json.loads(pathlib.Path(state_path).read_text(encoding="utf-8"))
    destination = pathlib.Path(output_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(
            {
                "processed": state["message"],
                "runtime": state["runtime"],
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"processed:{state['message']}")


if len(sys.argv) != 4 or sys.argv[1] not in {"seed", "process"}:
    raise SystemExit(
        "usage: python cli.py <seed|process> <input-or-state> <state-or-output>"
    )

if sys.argv[1] == "seed":
    seed(sys.argv[2], sys.argv[3])
else:
    process(sys.argv[2], sys.argv[3])
