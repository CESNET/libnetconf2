#!/bin/sh
cmake -DENABLE_TLS=ON -DENABLE_SSH=ON -DCMAKE_INSTALL_PREFIX:PATH=$INSTALL_TO/usr -DCMAKE_BUILD_TYPE:String="Debug" . && make && make install

