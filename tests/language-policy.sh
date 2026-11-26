#!/bin/sh
# Audit shipped files, not workstation caches. This is a source lint, not a sandbox.
set -eu
export LC_ALL=C
fail() { printf 'Source language policy: %s: %s\n' "$file" "$*" >&2; exit 1; }
if [ "${1-}" = --files ]; then
    shift
    for file do
        file=${file#./}
        [ ! -L "$file" ] || fail 'symlinks may hide unchecked sources'
        [ -e "$file" ] || continue  # tracked deletion
        [ -f "$file" ] || fail 'not a regular file'
        base=${file##*/}
        header=$(head -c 2 < "$file")
        shell=false
        if [ "$header" = '#!' ]; then
            IFS= read -r interpreter < "$file" || :
            case "$interpreter" in '#!/bin/sh'|'#!/usr/bin/env sh') shell=true ;; *) fail 'not a portable shell shebang' ;; esac
        fi
        case "$base" in
            *.sh) [ "$shell" = true ] || fail 'missing shell shebang'; kind=sh ;;
            CMakeLists.txt|*.cmake) kind=cmake ;;
            Makefile|*.mk) kind=make ;;
            *.c|*.cpp|*.cc|*.cxx|*.h|*.hpp|*.hh|*.hxx|*.hpp.in|*.h.in) kind=native ;;
            *.md|*.json|.gitignore|LICENSE|NOTICE) kind=data ;;
            *.*) fail 'not an allowed file type' ;;
            *) [ "$shell" = true ] || fail 'unknown extensionless file'; kind=sh ;;
        esac
        if [ "$kind" != sh ]; then
            [ "$shell" = false ] && [ ! -x "$file" ] || fail 'unexpected executable or shebang'
        fi
        if [ -s "$file" ] && ! grep -Iq '^' -- "$file"; then fail 'binary disguised as text'; fi
        if [ "$kind" = data ]; then
            case "$base" in *.json) cmake "-DINPUT=$PWD/$file" -P "$TURTLE_POLICY_TOOLS/check-json.cmake" || fail 'not JSON data' ;; esac
            continue
        fi
        if [ "$kind" = sh ]; then sh -n "./$file" || fail 'invalid shell syntax'; fi
        # Match command positions in shell/Make, CMake's COMMAND and C/C++ argv.
        bad='([p]ython([0-9.]+)?|[p]erl([0-9.]+)?|[r]uby|[l]ua([0-9.]+)?|[n]ode(js)?|[gmn]?[a]wk|[p]hp|[t]clsh|[r]script|[j]ulia|[d]eno|[l]uajit|[p]wsh)'
        delim='([[:space:]"<>;|(),]|$)'
        exe="([^[:space:]\"';|()]+/)?$bad$delim"
        case "$kind" in
            sh|make) re="(^[[:space:]@+-]*|[[:space:];|&(\`=\"'])$exe" ;;
            cmake) re="(COMMAND[[:space:]]+[\"']?$exe|find_(package|program)[[:space:]]*\\([[:space:]]*$bad([[:space:])]|$)|[$][{]([P]ython[0-9]*|[P]ERL|[R]uby|[L]UA|[A]WK|[N]ODE)_EXECUTABLE[}])" ;;
            native) re="[\"']$exe" ;;
        esac
        if grep -inE -- "$re" "$file" >&2; then fail 'foreign interpreter invocation'; fi
    done
    exit 0
fi
self=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)/$(basename -- "$0")
TURTLE_POLICY_TOOLS=$(dirname "$self")
export TURTLE_POLICY_TOOLS
cd -- "${1:-$TURTLE_POLICY_TOOLS/..}"
list=$(mktemp)
trap 'rm -f "$list"' EXIT
if [ -e .git ]; then
    git ls-files -z --cached > "$list"
    git ls-files -z --others --exclude-standard -- . ':(exclude,glob)implementations/*/**' >> "$list"
else
    # Source archives have no index. Skip known root-local paths from
    # .gitignore, without suppressing shared editor files or nested code.
    find . \( -path './.git' \
        -o \( -type d \( -path './.deps' -o -path './.omx' -o -path './.planning' -o -path './.vs' \
            -o \( -path './.submission-example.????????' ! -path './*/*' \) \
            -o -path './build' -o -path './build-tests' -o -path './cmake-build-*' \
            -o -path './out' -o -path './outputs' -o -path './CMakeFiles' -o -path './Testing' \
            -o -path './docs/for-paper' -o -path './docs/temp' -o -path './docs/references' \
            -o -path './implementations/*' \) \) \
        -o -path './.vscode/settings.json' -o -path './AGENTS.md' \
        -o -path './CMakeCache.txt' -o -path './cmake_install.cmake' \
        -o -path './CTestTestfile.cmake' -o -path './CMakeUserPresets.json' \
        -o -path './DartConfiguration.tcl' -o -path './compile_commands.json' \
        -o -path './build.ninja' -o -path './.ninja_deps' -o -path './.ninja_log' \
        -o -path './install_manifest.txt' \) -prune -o \( -type f -o -type l \) -print0 > "$list"
fi
xargs -0 -r sh "$self" --files < "$list"
