#!/bin/sh
set -e

sudo apt-get update -qq
sudo apt-get install -y zlib1g-dev
sudo apt-get install -y libssl-dev
sudo apt-get install -y libval-dev
sudo apt-get install -y valgrind

echo -n | openssl s_client -connect scan.coverity.com:443 | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' | sudo tee -a /etc/ssl/certs/ca-certificates.crt

# libssh
wget https://git.libssh.org/projects/libssh.git/snapshot/libssh-0.7.5.tar.gz
tar -xzf libssh-0.7.5.tar.gz
mkdir libssh-0.7.5/build && cd libssh-0.7.5/build
cmake -DCMAKE_INSTALL_PREFIX:PATH=/usr .. && make -j2 && sudo make install
cd ../..

# CMocka
wget https://cmocka.org/files/1.0/cmocka-1.0.1.tar.xz
tar -xJf cmocka-1.0.1.tar.xz
mkdir cmocka-1.0.1/build && cd cmocka-1.0.1/build
cmake -DCMAKE_INSTALL_PREFIX:PATH=/usr .. && make -j2 && sudo make install
cd ../..

git clone -b $TRAVIS_BRANCH https://github.com/CESNET/libyang.git
mkdir libyang/build && cd libyang/build
cmake -DCMAKE_INSTALL_PREFIX:PATH=/usr .. && make -j2 && sudo make install
cd ../..
