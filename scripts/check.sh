#!/usr/bin/env bash
# No downloads, global tuning, or root privileges. REPEAT=1 is a quick check.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
build=$(realpath -m -- "${TURTLE_BUILD_DIR:-$root/build-module}")
tests=$(realpath -m -- "${TURTLE_TEST_BUILD_DIR:-$root/build-tests-independent}")
jobs=${JOBS:-4}
repeat=${REPEAT:-20}
if [[ $build == "$tests" ]]; then echo '소스 빌드와 시험 빌드 폴더를 다르게 지정하십시오.' >&2; exit 2; fi
if [[ ! $repeat =~ ^[1-9][0-9]*$ ]]; then echo 'REPEAT는 양의 정수여야 합니다.' >&2; exit 2; fi
TURTLE_BUILD_DIR="$build" TURTLE_BUILD_TYPE=Release "$root/scripts/build.sh" module
TURTLE_TEST_BUILD_DIR="$tests" TURTLE_BUILD_TYPE=Debug "$root/scripts/build.sh" tests
ctest --test-dir "$tests" --output-on-failure --repeat "until-fail:$repeat" -j "$jobs"
python3 "$root/scripts/check-modules.py" --root "$root"
for script in "$root"/scripts/*.sh; do bash -n "$script"; done
if git -C "$root" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    git -C "$root" diff --check
else
    printf 'Git metadata absent; diff check unavailable for this source snapshot.\n'
fi
if [[ ${STATIC_CHECKS:-0} == 1 ]]; then "$root/scripts/static-check.sh" "$build"; fi
