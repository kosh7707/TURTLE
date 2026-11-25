#!/bin/sh
set -eu
guard=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)/language-policy.sh
root=$(mktemp -d)
trap 'rm -rf "$root"; rm -f "$root-log"' EXIT
cd "$root"
mkdir -p docs
printf '%s\n' '#!/bin/sh' 'printf "hello\\n"' > endpoint
printf '%s\n' 'int main(void) { return 0; }' > main.c
printf '%s\n' 'cmake_minimum_required(VERSION 3.20)' > CMakeLists.txt
printf '%s\n' '{"language":"not executable"}' > data.json
printf '%s\n' 'This is a note about interpreters.' > docs/note.md
pass() { sh "$guard" "$root"; }
reject() {
    if sh "$guard" "$root" > "$root-log" 2>&1; then
        printf 'Failed to reject %s\n' "$1" >&2; exit 1
    fi
    grep -F -- "$1:" "$root-log" >/dev/null || { cat "$root-log" >&2; exit 1; }
    rm "$1" "$root-log"
}
pass
# Archive users run the benchmark before auditing their source tree.
mkdir -p outputs/run.results/attempts/0/client src/outputs
printf 'READY\n' > outputs/run.results/attempts/0/client/control.log
pass
touch src/outputs/leaked.py
reject src/outputs/leaked.py
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
git init -q
printf '%s\n' '/cache/' '/outputs/' > .gitignore
mkdir cache
printf 'bad\n' > cache/hidden.rs
pass
git add -f cache/hidden.rs
reject cache/hidden.rs
touch outputs/tracked.py
git add -f outputs/tracked.py
reject outputs/tracked.py
