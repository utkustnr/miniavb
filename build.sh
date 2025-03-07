#!/bin/sh

CUR_DIR=$(pwd)

NDK_URL="https://dl.google.com/android/repository/android-ndk-r28-linux.zip"

OSSL_URL="https://github.com/openssl/openssl/releases/download/openssl-3.4.1/openssl-3.4.1.tar.gz"

[ ! -f android-ndk-r28-linux.zip ] && wget $NDK_URL

[ ! -d android-ndk-r28 ] && unzip android-ndk-r28-linux.zip

export ANDROID_NDK_ROOT=$CUR_DIR/android-ndk-r28

export PATH=$CUR_DIR/android-ndk-r28/toolchains/llvm/prebuilt/linux-x86_64/bin:$PATH

[ ! -f openssl-3.4.1.tar.gz ] && wget $OSSL_URL

[ ! -d openssl-3.4.1 ] && tar -xzf openssl-3.4.1.tar.gz

cd openssl-3.4.1

./Configure android-arm64 no-shared no-dso --prefix=$CUR_DIR/openssl-android

make -j$(nproc --all)

make install

cd ..

$CUR_DIR/android-ndk-r28/toolchains/llvm/prebuilt/linux-x86_64/bin/clang \
  --target=aarch64-linux-android21 \
  -O3 \
  -static \
  -I$CUR_DIR/openssl-android/include \
  -L$CUR_DIR/openssl-android/lib \
  -lcrypto \
  -o $CUR_DIR/miniavb \
  $CUR_DIR/miniavb.c

$CUR_DIR/android-ndk-r28/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-strip $CUR_DIR/miniavb
