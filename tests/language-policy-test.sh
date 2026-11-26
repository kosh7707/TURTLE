#!/bin/sh
set -eu
tests=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
guard=$tests/language-policy.sh
root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT
log=$root/probe.log
mkdir "$root/source"
cd "$root/source"
mkdir -p docs
printf '%s\n' '#!/bin/sh' 'printf "hello\\n"' > endpoint
printf '%s\n' 'int main(void) { return 0; }' > main.c
printf '%s\n' 'cmake_minimum_required(VERSION 3.20)' > CMakeLists.txt
printf '%s\n' '{"language":"not executable"}' > data.json
printf '%s\n' 'This is a note about interpreters.' > docs/note.md
pass() { sh "$guard" "$root/source"; }
reject() {
    # Keep the diagnostic outside the scanned tree when running without Git.
    if sh "$guard" "$root/source" > "$log" 2>&1; then
        printf 'Failed to reject %s\n' "$1" >&2; exit 1
    fi
    grep -F -- "$1:" "$log" >/dev/null || { cat "$log" >&2; exit 1; }
    rm "$1" "$log"
}
check_directory_only_patterns() {
    for path in .planning CMakeFiles Testing; do
        printf '%s\n' 'not a generated directory' > "$path"
        reject "$path"
        ln -s docs "$path"
        reject "$path"
    done
}
check_staging_depth() {
    mkdir -p .submission-example.abcdefgh .submission-example.x/abcdef
    touch .submission-example.abcdefgh/private.rs
    pass
    touch .submission-example.x/abcdef/leaked.rs
    reject .submission-example.x/abcdef/leaked.rs
}
pass
check_directory_only_patterns
check_staging_depth
# Archive users run the benchmark before auditing their source tree.
mkdir -p outputs/run.results/attempts/0/client src/outputs
printf 'READY\n' > outputs/run.results/attempts/0/client/control.log
pass
touch src/outputs/leaked.py
reject src/outputs/leaked.py
mkdir -p implementations/example-source/tools
touch implementations/example-source/tools/upstream.py
pass
touch implementations/tracked-by-boundary.py
reject implementations/tracked-by-boundary.py
# Only the root workstation locations are excluded; nested sources still count.
mkdir -p .planning src/.planning .vscode CMakeFiles Testing cmake-build-debug
printf '%s\n' local-plan > .planning/.active_plan
touch .planning/local.py CMakeFiles/local.log Testing/local.log cmake-build-debug/local.log
touch CMakeCache.txt CMakeUserPresets.json build.ninja .ninja_log
printf '%s\n' 'local jsonc settings' > .vscode/settings.json
printf '%s\n' '{"version":"2.0.0","tasks":[]}' > .vscode/tasks.json
pass
touch src/.planning/leaked.rs
reject src/.planning/leaked.rs
touch src/.ninja_log
reject src/.ninja_log
touch cmake-build-not-a-directory.py
reject cmake-build-not-a-directory.py
printf '%s\n' 'not JSON' > .vscode/tasks.json
reject .vscode/tasks.json
foreign=py'thon3'
printf '%s\n' 'print(1)' > probe.py
reject probe.py
printf '#!/usr/bin/env %s\n' "$foreign" > probe
reject probe
printf '#!/bin/sh\n%s -c something\n' "$foreign" > probe.sh
reject probe.sh
printf '#!/bin/sh\nprintf x | %s something\n' a'wk' > probe.sh
reject probe.sh
printf 'execute_process(COMMAND %s -c something)\n' "$foreign" > probe.cmake
reject probe.cmake
printf 'const char *cmd[] = {"%s", 0};\n' "$foreign" > probe.cpp
reject probe.cpp
printf '#!/bin/sh\n' > probe.json
reject probe.json
printf '{"x":true}\ntrailing code\n' > probe.json
reject probe.json
printf 'hello\n' > probe.json
reject probe.json
tar -czf docs/probe.tar.gz main.c
reject docs/probe.tar.gz
ln -s main.c probe.hpp
reject probe.hpp

check_starter_paths() {
    for dir in implementations tools/submission-starter; do
        mkdir -p "$dir"
        printf '%s\n' '#!/bin/sh' 'if' > "$dir/build.sh"
        reject "$dir/build.sh"
        cp main.c "$dir/implementation.cpp"
        chmod +x "$dir/implementation.cpp"
        reject "$dir/implementation.cpp"
    done
}
check_starter_paths

# Do not inherit the invoking worktree/index (e.g. when run by a Git hook).
git_env=$(git rev-parse --local-env-vars)
unset $git_env
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
git init -q --template=
cp "$tests/../.gitignore" .gitignore
pass
rm .planning/.active_plan .planning/local.py CMakeFiles/local.log Testing/local.log
rmdir .planning CMakeFiles Testing
check_directory_only_patterns
check_staging_depth
mkdir .planning
check_starter_paths
printf '%s\n' 'not JSON' > .vscode/tasks.json
reject .vscode/tasks.json
git add -f implementations/example-source/tools/upstream.py
reject implementations/example-source/tools/upstream.py
for file in .planning/.active_plan .planning/local.py .vscode/settings.json build.ninja outputs/tracked.py; do
    touch "$file"
    git add -f "$file"
    reject "$file"
done
