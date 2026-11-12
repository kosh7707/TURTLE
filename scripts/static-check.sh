#!/usr/bin/env bash
# 사용: static-check.sh [빌드 폴더] [프로젝트 폴더] [auto|cppcheck|clang-tidy|all]
# 이미 생성된 컴파일 데이터베이스만 읽으며 빌드나 다운로드는 하지 않습니다.
set -euo pipefail
root="${2:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)}"
build="${1:-$root/build}"
tool="${3:-auto}"
command -v python3 >/dev/null || { echo "python3가 필요합니다" >&2; exit 2; }
[[ -f "$build/compile_commands.json" ]] || {
    echo "compile_commands.json이 없습니다. CMake에서 CMAKE_EXPORT_COMPILE_COMMANDS=ON으로 구성하세요." >&2
    exit 2
}
case "$tool" in auto|cppcheck|clang-tidy|all) ;; *)
    echo "도구는 auto, cppcheck, clang-tidy, all 중 하나여야 합니다" >&2; exit 2 ;;
esac
temporary="$(mktemp -d)"
trap 'rm -rf -- "$temporary"' EXIT
python3 - "$root" "$build" "$temporary" <<'PY'
import json
from pathlib import Path
import sys
root, build, temporary = map(lambda p: Path(p).resolve(), sys.argv[1:])
commands = json.loads((build / "compile_commands.json").read_text())
selected, files = [], set()
for entry in commands:
    path = Path(entry["file"])
    if not path.is_absolute():
        path = Path(entry["directory"]) / path
    path = path.resolve()
    if not any(path.is_relative_to(root / component) for component in ("src", "implementations")):
        continue
    files.add(path)
    selected.append(entry)
if not selected:
    sys.exit("프로젝트 소스에 해당하는 컴파일 명령이 없습니다")
(temporary / "compile_commands.json").write_text(json.dumps(selected))
(temporary / "sources").write_bytes(b"".join(str(path).encode() + b"\0" for path in sorted(files)))
print(f"프로젝트 번역 단위 {len(selected)}개를 검사합니다 (외부 소스 제외)")
PY
if [[ "$tool" == auto ]]; then
    if command -v cppcheck >/dev/null; then tool=cppcheck
    elif command -v clang-tidy >/dev/null; then tool=clang-tidy
    else echo "cppcheck 또는 clang-tidy가 필요합니다" >&2; exit 2
    fi
fi
failed=0
if [[ "$tool" == cppcheck || "$tool" == all ]]; then
    command -v cppcheck >/dev/null || { echo "cppcheck가 없습니다" >&2; exit 2; }
    cppcheck --version
    cppcheck --project="$temporary/compile_commands.json" --std=c++20 \
        --enable=warning,performance,portability --inline-suppr \
        --suppress=missingIncludeSystem "--suppress=*:$root/third_party/*" \
        --error-exitcode=1 || failed=1
fi
if [[ "$tool" == clang-tidy || "$tool" == all ]]; then
    command -v clang-tidy >/dev/null || { echo "clang-tidy가 없습니다" >&2; exit 2; }
    clang-tidy --version
    while IFS= read -r -d '' source; do
        clang-tidy -p "$temporary" --checks='-*,clang-analyzer-*' \
            --warnings-as-errors='*' "$source" || failed=1
    done < "$temporary/sources"
fi
if (( failed )); then
    echo "FAIL: 정적 검사 ($tool); 위 진단을 확인하세요" >&2
    exit 1
fi
echo "PASS: 정적 검사 ($tool)"
