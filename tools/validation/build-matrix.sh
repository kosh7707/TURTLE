#!/bin/sh
# Research validation driver. Not used by bench.sh or the linker.
set -eu
export LC_ALL=C
umask 077

die() { printf '%s\n' "$*" >&2; exit 1; }
usage() {
    printf '%s\n' 'Usage: build-matrix.sh run SOURCE INPUTS NEW_MATRIX' \
        '       build-matrix.sh verify openssl|wolfssl|gnutls VENDOR_RUN_DIRECTORY'
    exit 2
}

# Use the exact archive names to avoid substituting local checkouts.
manifest() {
    case $1 in
        openssl)
            archive=openssl-2d1c10a592677ff34cdf60bd59c431d835a1fc26.tar.gz
            version='OpenSSL 4.2.0-dev (2d1c10a592677ff34cdf60bd59c431d835a1fc26)'
            header=openssl/opensslv.h
            libs='libssl libcrypto'
            ;;
        wolfssl)
            archive=wolfssl-5.9.4.tar.gz
            version='wolfSSL v5.9.4-stable'
            header=wolfssl/options.h
            libs=libwolfssl
            ;;
        gnutls)
            archive=gnutls-3.8.14.tar.xz
            version='GnuTLS 3.8.14'
            header=gnutls/gnutls.h
            libs=libgnutls
            ;;
        *) usage ;;
    esac
}

verify_inputs() (
    cd "$inputs"
    sha256sum --check - <<'HASHES'
7e2d258071f5db9620aa7ff34259331d004f7beafa3eb18560cfaf60acfbf02a  gnutls-3.8.14.tar.xz
42f6e95cad6ec532fd372391373363b62a14af6d771056dbfc86160e6dfff7aa  json-3.12.0.tar.xz
915a1844aea2c0ff3c15f16572fe110ff3840af0aa675f5e83c95b5ae85f4cc4  openssl-2d1c10a592677ff34cdf60bd59c431d835a1fc26.tar.gz
7256bfc89b183a75183806c7debfa203443873b0b4a562e1b80d68e01b45ac57  wolfssl-5.9.4.tar.gz
HASHES
)

verify_build() (
    manifest "$1"
    dir=$2 build=$2/job/build
    status=$(cat "$dir/bench.exit")
    [ "$status" = 0 ] || die "$1 bench exit $status"
    [ "$(cat "$build/native.exit")" = 0 ] && [ -s "$build/native.log" ] ||
        die "$1 recipe failed"
    for artifact in runs summary.json; do
        [ ! -e "$dir/job/$artifact" ] && [ ! -L "$dir/job/$artifact" ] ||
            die "$1 build-only job has runtime output $artifact"
    done

    module=$(sed -n 's/^module=//p' "$build/link-evidence.txt")
    object=$(sed -n 's/^object=//p' "$build/link-evidence.txt")
    [ -n "$module" ] && [ "$module" = "$(cat "$build/module.txt")" ] ||
        die 'module records disagree'
    case $object in
        "$build"/link.*/objects/*/implementation.o) [ -f "$object" ] || die 'missing bridge object' ;;
        *) die 'selected module did not record a private bridge object' ;;
    esac
    [ -f "$build/prefix/include/$header" ] || die "missing private SDK header $header"
    # GCC -MD escapes spaces in the dependency path, unlike GNU ld LOAD rows.
    sed 's/\\ / /g' "$build/implementation.d" |
        grep -F -- "$build/prefix/include/$header" > "$dir/private-header.txt"
    cat "$dir/private-header.txt"
    sha256sum --check "$build/expected-libs.sha256"
    [ -s "$build/expected-libs.txt" ] || die 'no staged runtime libraries'

    for role in client server; do
        [ -f "$build/bin/$role" ] && [ -x "$build/bin/$role" ] || die "not executable: $role"
        grep -Fx -- "LOAD $object" "$build/$role.map"
        for lib in $libs; do
            loaded=
            while IFS= read -r path; do
                case $path in
                    "$build/prefix/"*) ;;
                    *) die "non-private runtime path: $path" ;;
                esac
                case ${path##*/} in
                    "$lib".so.*)
                        grep -Fx -- "LOAD $path" "$build/$role.map"
                        loaded=yes
                        ;;
                esac
            done < "$build/expected-libs.txt"
            [ -n "$loaded" ] || die "$role missing staged $lib"
        done
    done

    # Preserve the build-only view even if the researcher later resumes the job.
    proof=$dir/build-only-proof
    mkdir "$proof"
    for artifact in client.map server.map implementation.d link-evidence.txt expected-libs.txt \
                    expected-libs.sha256 native.exit module.txt native-arguments candidates.tsv; do
        cp -p -- "$build/$artifact" "$proof/"
    done
    cp -p -- "$dir/tree/implementations/build.sh" "$proof/recipe.sh"
    tr '\000' '\n' < "$proof/native-arguments" > "$proof/native-argv.txt"
    sha256sum -- "$object" "$build/bin/client" "$build/bin/server" "$build/native.log" \
        > "$proof/build-files.sha256"
    printf '%s\n' "PASS $version; module=$module; no runs/ or summary.json present at verification"
)

copy_framework() {
    mkdir -p "$1/docs" "$1/implementations"
    for item in .gitignore CMakeLists.txt bench.sh src tools tests; do
        cp -a -- "$source/$item" "$1/"
    done
    cp -a -- "$source/docs/examples" "$1/docs/"
    starter=$1/tools/submission-starter
    cp -p -- "$starter/build.sh" "$starter/implementation.cpp" "$source/implementations/README.md" "$1/implementations/"
}

run_vendor() (
    vendor=$1 dir=$matrix/$1 tree=$matrix/$1/tree rc=0
    manifest "$vendor"
    mkdir "$dir"
    mkdir "$dir/tmp"
    copy_framework "$tree"
    mkdir "$tree/implementations/$vendor"
    tar xf "$inputs/$archive" --strip-components=1 -C "$tree/implementations/$vendor"
    "$tree/tools/init-submission-example.sh" "$vendor"
    printf 'version=%s\narchive=%s\nadditional native argv: none\n' "$version" "$archive" > "$dir/input.txt"

    cd "$tree"
    TMPDIR="$dir/tmp" TURTLE_BUILD_DIR="$dir/framework" \
        ./bench.sh --build-only --out "$dir/job" > "$dir/bench.log" 2>&1 || rc=$?
    printf '%s\n' "$rc" > "$dir/bench.exit"
    "$driver" verify "$vendor" "$dir" > "$dir/build-verification.log" 2>&1
)

run_contracts() (
    rc=0 tree=$matrix/contracts/tree dir=$matrix/contracts
    mkdir -p "$dir/tmp"
    copy_framework "$tree"
    export TMPDIR=$dir/tmp
    cmake -S "$tree" -B "$dir/build" -DBUILD_TESTING=ON \
        -DTURTLE_BUILD_REFERENCE=OFF -DTURTLE_TEST_SUBMISSION_E2E=ON > "$dir/configure.log" 2>&1
    ctest --test-dir "$dir/build" --output-on-failure --no-tests=error \
        -R '^(submission_entry_requires_inputs|submission_build_contract|submission_recipe_failure)$' \
        > "$dir/ctest.log" 2>&1 || rc=$?
    printf '%s\n' "$rc" > "$dir/ctest.exit"
    for test in submission_entry_requires_inputs submission_build_contract submission_recipe_failure; do
        grep -E -- "Test +#[0-9]+: +$test +[.]+ +Passed" "$dir/ctest.log"
    done
    exit "$rc"
)

[ "$#" -ge 1 ] || usage
case $1 in
    verify)
        [ "$#" = 3 ] || usage
        verify_build "$2" "$(realpath -e -- "$3")"
        ;;
    run)
        [ "$#" = 4 ] || usage
        driver=$(realpath -e -- "$0")
        source=$(realpath -e -- "$2")
        inputs=$(realpath -e -- "$3")
        matrix=$(realpath -m -- "$4")
        mkdir -- "$matrix"
        verify_inputs > "$matrix/input-checksums.log" 2>&1
        mkdir -p "$matrix/deps/cache"
        cp -- "$inputs/json-3.12.0.tar.xz" "$matrix/deps/cache/"
        cmake "-DDEPS_DIR=$matrix/deps" -DNAME=json -DVERSION=3.12.0 -DOFFLINE=ON \
            -P "$source/tools/dependencies.cmake" > "$matrix/json-bootstrap.log" 2>&1
        export CMAKE_PREFIX_PATH=$matrix/deps/prepared/json-3.12.0/install
        unset TURTLE_USE_MODULE
        run_contracts > "$matrix/contracts-verification.log" 2>&1 & pids=$!
        for vendor in openssl wolfssl gnutls; do
            run_vendor "$vendor" > "$matrix/$vendor.verify.log" 2>&1 & pids="$pids $!"
        done
        rc=0
        for pid in $pids; do wait "$pid" || rc=1; done
        exit "$rc"
        ;;
    *) usage ;;
esac
