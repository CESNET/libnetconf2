#!/bin/bash
# get latest upstream libnetconf2 version from github

RLS_URL=https://api.github.com/repos/CESNET/libnetconf2/releases
VERSION=$(curl -s $RLS_URL | grep tag_name | cut -d '"' -f 4 | sort --version-sort | tail -n 1)
VERSION=${VERSION#v}
echo $VERSION
