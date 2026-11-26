#!/bin/sh
set -eu
[ "$#" -ge 2 ] || { printf 'usage: build.sh WORK PREFIX [-Dname=value ...]\n' >&2; exit 2; }
work=$1 prefix=$2
shift 2
for arg do
    case $arg in
        -DCMAKE_INSTALL_*=*|-DCMAKE_STAGING_PREFIX*=*|-DUSE_STATIC_*_LIBRARY*=*|-DUSE_SHARED_*_LIBRARY*=*|\
        -DENABLE_PROGRAMS*=*|-DENABLE_TESTING*=*|-DGEN_FILES*=*|-DDISABLE_PACKAGE_CONFIG_AND_INSTALL*=*|\
        -DCMAKE_DISABLE_FIND_PACKAGE_Python*=*|-DCMAKE_EXPORT_NO_PACKAGE_REGISTRY*=*|-DCMAKE_EXPORT_PACKAGE_REGISTRY*=*)
            printf 'SDK layout option is set by this recipe: %s\n' "$arg" >&2; exit 2;;
        -DMBEDTLS_CONFIG_FILE*=*|-DMBEDTLS_USER_CONFIG_FILE*=*|-DTF_PSA_CRYPTO_CONFIG_FILE*=*|-DTF_PSA_CRYPTO_USER_CONFIG_FILE*=*)
            printf 'use the corresponding *_CONFIG_BASE_FILE to install the configuration header: %s\n' "$arg" >&2; exit 2;;
        -D?*=*) ;;
        *) printf 'expected one -Dname=value per argument: %s\n' "$arg" >&2; exit 2;;
    esac
done
cmake -S ./mbedtls -B "$work" -DCMAKE_BUILD_TYPE=Release "$@" \
    "-DCMAKE_INSTALL_PREFIX=$prefix" -DCMAKE_INSTALL_LIBDIR=lib \
    -DENABLE_PROGRAMS=OFF -DENABLE_TESTING=OFF -DGEN_FILES=OFF \
    -DUSE_SHARED_MBEDTLS_LIBRARY=ON -DUSE_STATIC_MBEDTLS_LIBRARY=OFF \
    -DDISABLE_PACKAGE_CONFIG_AND_INSTALL=OFF -DCMAKE_EXPORT_PACKAGE_REGISTRY=OFF -DCMAKE_EXPORT_NO_PACKAGE_REGISTRY=ON \
    -DCMAKE_DISABLE_FIND_PACKAGE_Python3=ON -DCMAKE_DISABLE_FIND_PACKAGE_PythonInterp=ON
cmake --build "$work" --parallel "${JOBS:-4}"
DESTDIR= cmake --install "$work"
pcdir=$prefix/lib/pkgconfig
version=$(sed -n 's/^Version: //p' "$pcdir/mbedtls.pc")
[ -n "$version" ]
cat > "$pcdir/mbedtls-sdk.pc" <<PC
Name: Mbed TLS SDK
Description: Public TLS, X.509 and PSA Crypto interfaces
Version: $version
Requires: mbedtls mbedx509 mbedcrypto
PC
