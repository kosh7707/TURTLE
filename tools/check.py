#!/usr/bin/env python3
"""부품 경계, Python 구문과 선택한 빌드의 clang-tidy를 검사한다."""
import ast
import json
from pathlib import Path
import subprocess
import sys
root = Path(__file__).resolve().parents[1]
build = Path(sys.argv[1]).resolve()
subprocess.run(["cmake", "-DROOT=" + str(root), "-P", str(root / "tests/boundaries.cmake")], check=True)
for folder in ("tools",):
    for path in (root / folder).rglob("*.py"):
        ast.parse(path.read_text(), filename=str(path))
sources = []
for row in json.loads((build / "compile_commands.json").read_text()):
    path = Path(row["file"])
    if path.suffix == ".cpp" and path.is_relative_to(root) and path.relative_to(root).parts[0] in ("src", "implementations", "tests"):
        sources.append(str(path))
log = build / "static-analysis.log"
with log.open("w") as output:
    result = subprocess.run(["clang-tidy", *sorted(set(sources)), "-p", str(build),
                             "--checks=-*,clang-analyzer-*,bugprone-use-after-move", "--warnings-as-errors=*"],
                            stdout=output, stderr=subprocess.STDOUT)
if result.returncode:
    print(log.read_text())
    raise SystemExit(result.returncode)
print(f"Python syntax and clang-tidy passed ({len(set(sources))} translation units): {log}")
