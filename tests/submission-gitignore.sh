#!/bin/sh
# Exercise ignore, add, and status behavior in an isolated Git repository.
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT
cd -- "$tmp"
# Hooks/worktrees may pass repository-local Git variables. This test must
# never initialize or add files in the caller's repository or index.
git_env=$(git rev-parse --local-env-vars)
unset $git_env
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
git init -q --template=
git config core.excludesFile /dev/null
git config core.fileMode true
# Simulate files already tracked before the workspace-only rules were added.
mkdir tests
touch tests/already-tracked.cpp task.md
git add -- tests/already-tracked.cpp task.md
cp -- "$root/.gitignore" .
fail() { printf '%s\n' "$*" >&2; exit 1; }

# The actual entry files must be visible to Git and remain so after editing.
set -- implementations/README.md implementations/build.sh implementations/implementation.cpp \
    CMakePresets.json docs/new-note.md src/new-feature.cpp nested/tests/new-test.cpp nested/task.md \
    .vscode/tasks.json
for file do
    mkdir -p -- "$(dirname -- "$file")"
    touch -- "$file"
    if git check-ignore -q -- "$file"; then fail "Versionable file is ignored: $file"; fi
done
chmod +x implementations/build.sh
git add -- .gitignore "$@"
git ls-files --stage -- implementations/build.sh | grep -Eq '^100755 '
printf '%s\n' '// Changed locally' > implementations/implementation.cpp
git status --porcelain -- implementations/implementation.cpp | grep -Fx 'AM implementations/implementation.cpp' >/dev/null

# Build noise and private inputs must not appear after an ordinary add.
set -- implementations/unnamed-fork/library.cpp implementations/credentials/private.key \
    implementations/local-override.cpp implementations/private.pem \
    .submission-example.ABC12345/old/implementation.cpp .deps/download/cache .omx/state.json .planning/session/progress.md .vscode/settings.json .vs/session \
    build/generated.cpp build-tests/CTestTestfile.cmake cmake-build-debug/CMakeCache.txt \
    out/report outputs/job/summary.json CMakeCache.txt CMakeFiles/CMakeOutput.log \
    cmake_install.cmake CTestTestfile.cmake CMakeUserPresets.json DartConfiguration.tcl Testing/Temporary/LastTest.log \
    compile_commands.json build.ninja .ninja_deps .ninja_log install_manifest.txt \
    tests/new-test.cpp tests/fixtures/Makefile
for file do
    mkdir -p -- "$(dirname -- "$file")"
    touch -- "$file"
    git check-ignore -q -- "$file" || fail "Local file is not ignored: $file"
done
git add -- .
[ -z "$(git ls-files -- "$@")" ] || fail 'Ordinary git add staged a private/generated file'
[ -z "$(git status --porcelain -- "$@")" ] || fail 'Private/generated files appear in ordinary status'
printf '%s\n' 'PASS: check-ignore, git add, executable starter mode, and tracked starter edits'

# Adding workspace-only rules must not hide edits to existing tracked files.
for file in tests/already-tracked.cpp task.md; do
    printf '%s\n' 'Changed locally' > "$file"
    git status --porcelain -- "$file" | grep -Fx "AM $file" >/dev/null ||
        fail "Edit to previously tracked file is hidden: $file"
done

# Check a newly created root task.md separately, so it has no index entry.
mkdir "$tmp/new-workspace"
(
    cd "$tmp/new-workspace"
    git init -q --template=
    cp -- "$root/.gitignore" .
    touch task.md
    git check-ignore -q -- task.md || fail 'New root task.md is not ignored'
    git add -- .
    [ -z "$(git ls-files -- task.md)" ] || fail 'Ordinary git add staged root task.md'
    [ -z "$(git status --porcelain -- task.md)" ] || fail 'New root task.md appears in ordinary status'
)
printf '%s\n' 'PASS: new root tests and task.md are ignored, tracked edits remain visible, and nested paths are versionable'

# The old ignore rules hid user-owned entry files. Git's default fast-forward
# may replace them when the incoming revision starts tracking those names.
cd -- "$tmp"
git init -q --template= --initial-branch=old upgrade
cd upgrade
git config user.name 'TURTLE test'
git config user.email 'turtle-test@example.invalid'
mkdir implementations
printf '%s\n' '/implementations/*' '!/implementations/README.md' > .gitignore
touch implementations/README.md
git add -- .
git commit -qm 'Pre-starter ignore rule'
previous=$(git rev-parse HEAD)
git checkout -qb incoming
cp -- "$root/.gitignore" .
printf '%s\n' '#!/bin/sh' 'exit 2' > implementations/build.sh
printf '%s\n' '// Incoming starter' > implementations/implementation.cpp
chmod +x implementations/build.sh
git add -- .
git commit -qm 'Track the starter pair'
incoming=$(git rev-parse HEAD)
git checkout -q old

printf '%s\n' '#!/bin/sh' 'exit 29' > implementations/build.sh
printf '%s\n' '// Local native bridge' > implementations/implementation.cpp
chmod +x implementations/build.sh
cp -- implementations/build.sh implementations/implementation.cpp "$tmp/"
for file in implementations/build.sh implementations/implementation.cpp; do
    git check-ignore -q -- "$file" || fail "Upgrade fixture is not ignored: $file"
done
test -z "$(git status --porcelain)" || fail 'Old status unexpectedly exposes custom files'
if LC_ALL=C git merge --ff-only --no-overwrite-ignore incoming > "$tmp/merge.log" 2>&1; then
    fail 'Protected fast-forward overwrote the hidden custom submission'
fi
for file in implementations/build.sh implementations/implementation.cpp; do
    grep -Fq -- "$file" "$tmp/merge.log" || { cat "$tmp/merge.log" >&2; fail "Merge did not report $file"; }
    cmp -- "$file" "$tmp/${file##*/}"
done
test "$(git rev-parse HEAD)" = "$previous"
test -x implementations/build.sh
test -z "$(git status --porcelain)"
printf '%s\n' 'PASS: fast-forward with --no-overwrite-ignore rejected both conflicts and preserved old HEAD and custom files'

git merge -q --ff-only incoming
test "$(git rev-parse HEAD)" = "$incoming"
for file in implementations/build.sh implementations/implementation.cpp; do
    git cat-file blob "HEAD:$file" > "$tmp/expected"
    cmp -- "$file" "$tmp/expected"
    if cmp -s -- "$file" "$tmp/${file##*/}"; then fail "Default fast-forward did not reproduce the risk: $file"; fi
done
printf '%s\n' 'PASS: default fast-forward replaced both ignored files in the disposable negative control'
