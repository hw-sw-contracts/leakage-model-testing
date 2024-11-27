#!/usr/bin/env bash
set -eu

# you will need to install the following:
#  standard build/dev tools (git, make, etc)
#  gcc
#  clang
#  jasminc (https://github.com/jasmin-lang/jasmin/wiki/Installation-instructions)
#  rustc/cargo (https://www.rust-lang.org/tools/install)

hash=
function savehash() {
   if [[ -f $1 ]]; then
       hash=$(sha256sum $1)
   fi
}


function checkhash() {
   local files
   if [[ "$hash" != $(sha256sum $1) ]]; then
       files=$( ls -1d ../violations_db/*-$1/dumps 2>/dev/null )
       if [[ $? -eq 0 ]]; then
           echo Removing:
           echo "$files"
           rm -rf ../violations_db/*-$1/dumps
       fi
   fi
}

function build_cc_models() {
   if [[ ! -e  cc_models.so ]]; then
       echo "Building cache compression models"
       clang -O3 -shared cc_models.c -o cc_models.so
   else
       echo "cache compression models already built"
   fi
}

function build_libsodium() {
   if [[ ! -d "libsodium-1.0.18" ]]; then
       echo "Downloading libsodium"
       wget https://download.libsodium.org/libsodium/releases/libsodium-1.0.18.tar.gz
       tar -xf libsodium-1.0.18.tar.gz
   else
       echo "Libsodium source already present"
   fi


   libsodium_lib="libsodium-1.0.18/src/libsodium/.libs/"
   libsodium_include="libsodium-1.0.18/src/libsodium/include/"


   if [[ ! -d "${libsodium_lib}" ]]; then
       echo "Building libsodium"
       cd libsodium-1.0.18
       ./configure --disable-asm
       make -j$(nproc)
       cd ..
       cp libsodium-1.0.18/src/libsodium/.libs/libsodium.so .
   else
       echo "Libsodium already built"
   fi


   echo "Building libsodium test program"
   gcc libsodium.c \
       ${libsodium_lib}/libsodium.a \
       -I ${libsodium_include} \
       -static \
       -lpthread \
       -o libsodium

    if [ ! -e libsodium.so ]; then
        cp libsodium-1.0.18/src/libsodium/.libs/libsodium.so .
    fi
}

function build_cryptlib() {
   NAME=cryptlib
   DIR=cryptlib-3.4.6
   if [[ ! -d $DIR ]]; then
       echo "Downloading $NAME"
       wget 'https://cryptlib-release.s3-ap-southeast-1.amazonaws.com/cryptlib346.zip'
       unzip -q -a -d $DIR cryptlib346.zip
   else
       echo "$NAME source already present"
   fi


   if [[ ! -e "$DIR/libcl.a" ]]; then
       echo "Building cryptlib"
       cd $DIR
       # XXX debug is needed to get static libs I think, need to double check
       make debug -j$(nproc)
       cd ..
       cp $DIR/libcl.a .
   else
       echo "$NAME already built"
   fi


   echo "Building $NAME test program"
   savehash cryptlib
   clang -fsanitize=safe-stack cryptlib.c \
       $DIR/libcl.a \
       -I $DIR/ \
       -static \
       -lpthread \
       -o cryptlib
}

function build_nettle() {
   NAME=nettle
   DIR=nettle-3.8
   TARGET=libnettle.a
   GMP_NAME=gmp
   GMP_DIR=gmp-6.2.1
   GMP_TARGET=libgmp.a
   HOGWEED_TARGET=libhogweed.a
   if [[ ! -d $DIR ]]; then
       echo "Downloading $NAME"
       wget 'https://ftp.gnu.org/gnu/nettle/nettle-3.8.tar.gz'
       tar -xf nettle-3.8.tar.gz
   else
       echo "$NAME source already present"
   fi

   if [[ ! -d $GMP_DIR ]]; then
       echo "Downloading $GMP_NAME"
       wget 'https://ftp.acc.umu.se/mirror/cygwin/x86_64/release/gmp/gmp-6.2.1-1-src.tar.xz'
       tar -xf gmp-6.2.1-1-src.tar.xz
       tar -I zstd -xf gmp-6.2.1-1.src/gmp-6.2.1.tar.zst
   else
       echo "$GMP_NAME source already present"
   fi

   if [[ ! -e  "$GMP_DIR/.libs/$GMP_TARGET" ]]; then
       echo "Building $GMP_NAME" ; cd $GMP_DIR
       ./configure
       make
       cd ..
   else
       echo "$GMP_NAME already built"
   fi

   if [[ ! -e  "$DIR/$TARGET" ]]; then
       echo "Building $NAME" ; cd $DIR
       gmppath=$(realpath "$GMP_DIR")
       ./configure --with-include-path="$gmppath" --with-lib-path="$gmppath"/.libs
       make
       cd ..
   else
       echo "$NAME already built"
   fi


   echo "Building $NAME test program"
   savehash nettle
   clang -fsanitize=safe-stack nettle.c \
       ${DIR}/${TARGET} \
       ${DIR}/${HOGWEED_TARGET} \
       ${GMP_DIR}/.libs/${GMP_TARGET} \
       -I ${GMP_DIR} \
       -I ${DIR} \
       -static \
       -lpthread \
       -o nettle
}


function build_libjade() {
   NAME=libjade
   DIR=libjade
   TARGET=libjade.a

   if command -v jasminc &> /dev/null; then
       if [[ ! -d $DIR ]]; then
           git clone https://github.com/formosa-crypto/libjade.git
           cd libjade
           git checkout 198a8c8f5a3413d8cdeeb52843f01239a80ee81c
           cd ..
       else
           echo "$NAME source already present"
       fi
   else
       echo "Please install the jasmin compiler before preceding"
       return
   fi


   if [[ ! -e  "$DIR/src/$TARGET" ]]; then
       echo "Building $NAME" ; cd $DIR/src
       make
       cd ../..
   else
       echo "$NAME already built"
   fi


   echo "Building $NAME test program"
   clang -fsanitize=safe-stack libjade.c \
       ${DIR}/src/${TARGET} \
       -I ${DIR}/src \
       -static \
       -lpthread \
       -o jade
}

function build_rust_crypto() {
   NAME=rust
   DIR=crypto
   TARGET=libcrypto.a
   if [ ! -e $NAME ]; then
        cd $DIR
        cargo install --force cbindgen
        cargo build --release
        cbindgen --config cbindgen.toml --crate crypto --lang c --output crypto.h
        cd ..
   fi


   echo "Building $NAME test program"
   clang -fsanitize=safe-stack -g crypto_rust.c \
       ${DIR}/target/release/${TARGET} \
       -lc -I ${DIR}/ \
       -static \
       -lpthread \
       -o rust
}

function build_all(){
    build_cc_models
    build_libsodium
    build_nettle
    build_cryptlib
    build_libjade
    build_rust_crypto
}

build_all

# boring SSL: 14aa0de18f638a92be13597bc1b8a95ca8fcf8a4 (master as of Mon Oct 17 14:18 CEST 2022)
#             https://boringssl.googlesource.com/boringssl/+archive/14aa0de18f638a92be13597bc1b8a95ca8fcf8a4.tar.gz
# see also : https://en.wikipedia.org/wiki/Comparison_of_cryptography_libraries
# see also : https://en.wikipedia.org/wiki/Comparison_of_TLS_implementations

