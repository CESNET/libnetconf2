#!/bin/sh
set -e

sudo apt-get update -qq
sudo apt-get install -y zlib1g-dev
sudo apt-get install -y libssl-dev
sudo apt-get install -y libval-dev
sudo apt-get install -y valgrind
sudo apt-get install -y osc

echo -n | openssl s_client -connect scan.coverity.com:443 | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' | sudo tee -a /etc/ssl/certs/ca-certificates.crt

# libssh
wget https://www.libssh.org/files/0.8/libssh-0.8.5.tar.xz
tar -xJf libssh-0.8.5.tar.xz
mkdir libssh-0.8.5/build && cd libssh-0.8.5/build
cmake -DCMAKE_INSTALL_PREFIX:PATH=/usr .. && make -j2 && sudo make install
cd ../..

# CMocka
wget https://cmocka.org/files/1.1/cmocka-1.1.1.tar.xz
tar -xJf cmocka-1.1.1.tar.xz
mkdir cmocka-1.1.1/build && cd cmocka-1.1.1/build
cmake -DCMAKE_INSTALL_PREFIX:PATH=/usr .. && make -j2 && sudo make install
cd ../..

if [[ "$TRAVIS_BRANCH" = "master" ]]; then LY_BRANCH="master"; else LY_BRANCH="devel"; fi
git clone -b $LY_BRANCH https://github.com/CESNET/libyang.git
mkdir libyang/build && cd libyang/build
cmake -DCMAKE_INSTALL_PREFIX:PATH=/usr .. && make -j2 && sudo make install
cd ../..
