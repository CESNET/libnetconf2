#!/bin/bash
set -ex

version=`pkg-config --modversion libnetconf2`
echo "$version" | grep '2\.[0-9.]\+'
