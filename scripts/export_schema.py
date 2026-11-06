"""Write the report's JSON Schema to docs/schema/. A test fails if this file is out of date.

uv run python scripts/export_schema.py
"""

from __future__ import annotations

import json
from pathlib import Path

from lookfirst.verdict.schema import SCHEMA_VERSION, report_json_schema

SCHEMA_FILE = (
    Path(__file__).resolve().parent.parent / "docs" / "schema" / f"report-{SCHEMA_VERSION}.json"
)


def schema_text() -> str:
    return json.dumps(report_json_schema(), indent=2, sort_keys=True) + "\n"


def main() -> None:
    SCHEMA_FILE.parent.mkdir(parents=True, exist_ok=True)
    SCHEMA_FILE.write_text(schema_text(), encoding="utf-8")
    print(f"wrote {SCHEMA_FILE.relative_to(SCHEMA_FILE.parent.parent.parent)}")


if __name__ == "__main__":
    main()
