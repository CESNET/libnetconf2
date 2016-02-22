#!/bin/bash
ABI_MON=abi-monitor
ABI_TRK=abi-tracker

which $ABI_MON > /dev/null || exit 1
which $ABI_TRK > /dev/null || exit 1

if test -n "$2"; then
	VER1="$1"
	VER2="$2"
elif test -n "$1"; then
	if test "$1" = "help" -o "$1" = "-h" -o "$1" = "--help"; then
		echo Usage:
		echo \t$0 [number of last versions]
		echo \t$0 [version1] [version2]
		exit 0
	fi
	LIMIT="-limit $1"
	l=$1
fi

if [ -e gitrepo ]; then
	cd gitrepo
	git pull
	cd -
else
	git clone https://github.com/CESNET/libnetconf2.git gitrepo
fi
test -e packages || mkdir packages
test -e src/libnetconf2 || mkdir -p src/libnetconf2
rm -rf src/libnetconf2/*

cd gitrepo
git checkout devel
VERSIONS=`git log --grep=VERSION --oneline | sed 's/ .* /_/'`
cd -
for i in $VERSIONS; do
	if test "$l" = "0"; then
		rm -rf abi_dump/libnetconf2/${i//*_}
		rm -rf installed/libnetconf2/${i//*_}
	else
		test -n "$l" && l=$(($l-1))
		if test -n "$VER1"; then
			if test "$VER1" != "${i//*_}" -a "$VER2" != "${i//*_}"; then
				rm -rf abi_dump/libnetconf2/${i//*_}
				rm -rf installed/libnetconf2/${i//*_}
				continue
			fi
		fi
		if test ! -f packages/libnetconf2-${i//*_}.tgz; then
			cd gitrepo
			git checkout ${i//_*}
			cd -
			tar -czf packages/libnetconf2-${i//*_}.tgz gitrepo
		fi
		cp packages/libnetconf2-${i//*_}.tgz src/libnetconf2/
	fi
done

cp libnetconf2.json libnetconf2.aux
abi-monitor -get -build $LIMIT libnetconf2.aux
abi-tracker -build libnetconf2.aux
rm -rf libnetconf2.aux

