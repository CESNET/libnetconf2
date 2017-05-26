#!/bin/sh
set -e

#install dependencies using homebrew
brew update
brew upgrade openssl
brew upgrade pcre

# libssh
wget https://git.libssh.org/projects/libssh.git/snapshot/libssh-0.7.5.tar.gz
tar -xzf libssh-0.7.5.tar.gz
mkdir libssh-0.7.5/build && cd libssh-0.7.5/build
cmake -DOPENSSL_LIBRARIES=/usr/local/opt/openssl/lib -DOPENSSL_INCLUDE_DIR=/usr/local/opt/openssl/include .. && make -j2 && sudo make install
cd ../..

# CMocka
git clone git://git.cryptomilk.org/projects/cmocka.git
mkdir cmocka/build && cd cmocka/build
cmake .. && make -j2 && sudo make install
cd ../..

git clone -b $TRAVIS_BRANCH https://github.com/CESNET/libyang.git
mkdir libyang/build && cd libyang/build
cmake .. && make -j2 && sudo make install
cd ../..
