#!/bin/sh
# Exercise selection in a source archive without changing the live submission.
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
tmp=$(mktemp -d)
trap 'rc=$?; if [ "$rc" != 0 ] && [ -f "$tmp/log" ]; then cat "$tmp/log" >&2; fi; rm -rf -- "$tmp"' EXIT
tree="$tmp/source tree"
slot="$tree/implementations"
examples="$tree/docs/examples/submissions"
starter="$tree/tools/submission-starter"
mkdir -p "$slot/native" "$examples" "$starter"
cp -- "$root/tools/init-submission-example.sh" "$tree/tools/"
cp -a -- "$root/docs/examples/submissions/openssl" "$root/docs/examples/submissions/mbedtls" "$examples/"
# Deliberately include a marker; edited content must still be recognized as work.
printf '%s\n' '#!/bin/sh' '# TURTLE starter' > "$starter/build.sh"
printf '%s\n' '// TURTLE starter' > "$starter/implementation.cpp"
chmod 755 "$starter/build.sh"
printf 'preserve native source\n' > "$slot/native/sentinel"
setup() {
    cp -p -- "$starter/build.sh" "$starter/implementation.cpp" "$slot/"
}
run() {
    expected=$1; shift
    rc=0
    (cd /; "$tree/tools/init-submission-example.sh" "$@") >"$tmp/log" 2>&1 || rc=$?
    [ "$rc" = "$expected" ] || { echo "Expected status $expected, got $rc" >&2; exit 1; }
}
same_starter() {
    cmp -s -- "$starter/build.sh" "$slot/build.sh"
    cmp -s -- "$starter/implementation.cpp" "$slot/implementation.cpp"
}
same_example() {
    cmp -s -- "$examples/openssl/build.sh" "$slot/build.sh"
    cmp -s -- "$examples/openssl/implementation.cpp" "$slot/implementation.cpp"
    [ "$(stat -c %a "$slot/build.sh")" = 755 ]
    [ "$(stat -c %a "$slot/implementation.cpp")" = 644 ]
}
setup
for name in ../openssl openssl/ foo..bar -openssl mbedtls missing; do
    run 2 "$name"
    same_starter
done
run 2 mbedtls
grep -Fiq 'implementation.cpp' "$tmp/log"
run 2
same_starter

printf '// user edit\n' >> "$slot/implementation.cpp"
cp -- "$slot/implementation.cpp" "$tmp/user-bridge"
run 2 openssl
grep -Fq 'implementation.cpp' "$tmp/log"
cmp -s -- "$starter/build.sh" "$slot/build.sh"
cmp -s -- "$tmp/user-bridge" "$slot/implementation.cpp"

rm -- "$slot/implementation.cpp"
ln -s "$tmp/user-bridge" "$slot/implementation.cpp"
run 2 openssl
test -L "$slot/implementation.cpp"
cmp -s -- "$starter/build.sh" "$slot/build.sh"
rm -- "$slot/implementation.cpp"
mkdir "$slot/implementation.cpp"
run 2 openssl
rmdir "$slot/implementation.cpp"
cmp -s -- "$starter/build.sh" "$slot/build.sh"

# Source archive mode, partial untouched slot and a spaced checkout path.
run 0 openssl
same_example
run 2 openssl
same_example
rm -- "$slot/build.sh" "$slot/implementation.cpp"
run 0 openssl
same_example

mv -- "$slot" "$tmp/actual"
ln -s "$tmp/actual" "$slot"
run 2 openssl
test -L "$slot"
cmp -s -- "$examples/openssl/build.sh" "$tmp/actual/build.sh"
rm -- "$slot"
mv -- "$tmp/actual" "$slot"

# Force publication of the second file to fail. The first one must roll back.
setup
mkdir "$tmp/bin"
cat > "$tmp/bin/mv" <<'SH'
#!/bin/sh
for arg do
    case "$arg" in
        */new/implementation.cpp) exit 1;;
    esac
done
exec /usr/bin/mv "$@"
SH
chmod +x "$tmp/bin/mv"
PATH="$tmp/bin:$PATH" run 1 openssl
same_starter
rm -- "$slot/build.sh"
PATH="$tmp/bin:$PATH" run 1 openssl
test ! -e "$slot/build.sh"
cmp -s -- "$starter/implementation.cpp" "$slot/implementation.cpp"
grep -Fxq 'preserve native source' "$slot/native/sentinel"
test "$(find "$tree" -name '.submission-example.*' -print)" = ''

# A destination that appears before the second no-clobber rename wins;
# the first file rolls back and the displaced original remains recoverable.
setup
cat > "$tmp/bin/mv" <<'SH'
#!/bin/sh
for arg do
    case "$arg" in
        */new/implementation.cpp) printf '// late user edit\n' > implementation.cpp;;
    esac
done
exec /usr/bin/mv "$@"
SH
PATH="$tmp/bin:$PATH" run 2 openssl
grep -Fxq '// late user edit' "$slot/implementation.cpp"
cmp -s -- "$starter/build.sh" "$slot/build.sh"
preserved=$(find "$tree" -path '*/.submission-example.*/old/implementation.cpp' -print)
test -n "$preserved"
cmp -s -- "$starter/implementation.cpp" "$preserved"
grep -Fq 'Preserved staging and any originals' "$tmp/log"
printf '%s\n' 'PASS: explicit selection, edited-file/unsafe-path refusals, rollback, and native source preservation'
