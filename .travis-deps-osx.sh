#!/bin/sh
set -e

#install dependencies using homebrew
brew update
brew upgrade openssl

# libssh
wget https://www.libssh.org/files/0.8/libssh-0.8.5.tar.xz
tar -xJf libssh-0.8.5.tar.gz
mkdir libssh-0.8.5/build && cd libssh-0.8.5/build
cmake -DOPENSSL_LIBRARIES=/usr/local/opt/openssl/lib -DOPENSSL_INCLUDE_DIR=/usr/local/opt/openssl/include .. && make -j2 && sudo make install
cd ../..

# CMocka
git clone git://git.cryptomilk.org/projects/cmocka.git
mkdir cmocka/build && cd cmocka/build
cmake .. && make -j2 && sudo make install
cd ../..

if [[ "$TRAVIS_BRANCH" = "master" ]]; then LY_BRANCH="master"; else LY_BRANCH="devel"; fi
git clone -b $LY_BRANCH https://github.com/CESNET/libyang.git
mkdir libyang/build && cd libyang/build
cmake .. && make -j2 && sudo make install
cd ../..
