# libnetconf2 – The NETCONF protocol library

[![BSD license](https://img.shields.io/badge/License-BSD-blue.svg)](https://opensource.org/licenses/BSD-3-Clause)
[![Build Status](https://secure.travis-ci.org/CESNET/libnetconf2.png?branch=master)](http://travis-ci.org/CESNET/libnetconf2)
[![Coverity Scan Build Status](https://scan.coverity.com/projects/7642/badge.svg)](https://scan.coverity.com/projects/7642)

**libnetconf2** is a NETCONF library in C intended for building NETCONF clients
and servers. NETCONF is the [NETwork CONFiguration protocol]
(http://trac.tools.ietf.org/wg/netconf/trac/wiki) introduced by IETF.

The library provides functions to connect NETCONF client and server to each
other via SSH and to send, receive and process NETCONF messages. In contrast
to the [previous libnetconf library](https://github.com/CESNET/libnetconf),
**libnetconf2** does not include NETCONF datastore implementation. This
functionality is left specific to the NETCONF server implementation.

**libnetconf2** is maintained and further developed by the [Tools for
Monitoring and Configuration](https://www.liberouter.org/) department of
[CESNET](http://www.ces.net/). Any testing of the library is welcome. Please
inform us about your experiences with using **libnetconf2** via the
[issue tracker](https://github.com/CESNET/libnetconf/issues).

**libnetconf2** is being developed with experiences gained from the development
of the [libnetconf](https://github.com/CESNET/libnetconf) library. This
previous generation of our NETCONF library is built on libxml2, used to
internally represent all the data. In **libnetconf2**, we have completely
replaced libxml2 by [libyang](https://github.com/CESNET/libyang). The libyang
library is much more efficient in work with YANG modeled data (which is the
case of NETCONF messages) and this advantage then applies also to
**libnetconf2**. The library is connected with YANG, so for example data
validation according to the provided YANG schemas is done internally instead
of using external DSDL tools (as it was in the first generation of libnetconf).

**libnetconf2** is currently being developed, and some (server-side) functions
are not yet implemented. Feedback and bug reports concerning problems not
mentioned here are appreciated via the issue tracker.

# Installation

## Required Dependencies

Install the following libraries and tools the libnetconf2 depends on.

### libyang
Follow the [libyang instructions](https://github.com/CESNET/libyang/blob/master/README.md),
in short:
```
$ git clone https://github.com/CESNET/libyang.git
$ cd libyang; mkdir build; cd build
$ cmake ..
$ make
# make install
```

### libssh
Required version is at least 0.6.4. This dependency can be removed by disabling
SSH support (see the [Build Options](#build-options) section). Below si the basic
sequence of commands for compiling and installing it from source. However, there
are packages for certain Linux distributions available [here](https://www.libssh.org/get-it/).
```
$ git clone http://git.libssh.org/projects/libssh.git
$ cd libssh; mkdir build; cd build
$ cmake ..
$ make
# make install
```

### OpenSSL
This dependency is required when the TLS support is enabled, which it is by
default but libssh requires it too. So, to remove this dependency, you need
to disable both SSH and TLS (see the [Build Options](#build-options) section).

OpenSSL is a standard part of the most distribution, so ask your package
manager for OpenSSL package including the necessary development files
(usually -dev or -devel package).

## Optional Dependencies

### libval (part of the DNSSEC-Tools suite)
It is required only if DNSSEC SSHFP retrieval is enabled (it is disabled by
default, see the [Build Options](#build-options) section).

The easier way of installing it is as the libval-dev package (or a part of
the dnssec-tools package), if you can find it for your distribution. Packages
for some distributions or the source can be downloaded from [here](https://www.dnssec-tools.org/download/).

### cmocka
For running the tests (see the [Tests](#tests) section for more information).
```
$ git clone git://git.cryptomilk.org/projects/cmocka.git
$ cd cmocka
$ git checkout tags/cmocka-1.0.1
$ mkdir build; cd build
$ cmake ..
$ make
# make install
```

### Doxygen
For building the library documentation.

Doxygen is a standard part of the most distribution, so ask your package
manager for doxygen package.

## Building libnetconf2

```
$ mkdir build; cd build
$ cmake ..
$ make
# install
```

The library documentation can be generated directly from the source codes using
Doxygen tool:
```
$ make doc
```

## Build Options

There are various options to change result of building.

### Changing Compiler

Set `CC` environment variable:

```
$ CC=/usr/bin/clang cmake ..
```

### Installation Prefix

By default, the library is installed with the `/usr/local` prefix, to change
it, use the following option:
```
$ cmake -DCMAKE_INSTALL_PREFIX:PATH=/usr ..
```

### Transport Protocol Support

The NETCONF protocol specification allows to use the protocol on top of
several transport protocols. **libnetconf2** provides support for SSH and
TLS transport. By default, both SSH and TLS transport is enabled. Disabling
and enabling both the transport protocols can be made
in the same way. The following command has actually the same effect as
specifying no option since it specifies the default settings.
```
$ cmake -DENABLE_TLS=ON -DENABLE_SSH=ON ..
```

### DNSSEC SSHFP Retrieval

In SSH connections, if the remote NETCONF server supports it and it is
enabled, it is possible to safely retrieve server host key fingerprints
using DNSSEC and automatically consider them to be trusted without any
interaction. Enable it with the following command.
```
$ cmake -DENABLE_DNSSEC=ON ..
```

### Build Modes

There are two build modes:
* Release.
  This generates library for the production use without any debug information.
* Debug.
  This generates library with the debug information and disables optimization
  of the code.

The `Debug` mode is currently used as the default one. to switch to the
`Release` mode, enter at the command line:
```
$ cmake -D CMAKE_BUILD_TYPE:String="Release" ..
```
### CMake Notes

Note that, with CMake, if you want to change the compiler or its options after
you already ran CMake, you need to clear its cache first - the most simple way
to do it is to remove all content from the 'build' directory.

## Tests

The repository includes several tests built with [cmocka](https://cmocka.org/).
The tests can be found in `tests` subdirectory and they are designed for
checking library functionality after code changes.

The tests are by default built in the `Debug` build mode by running
```
$ make
```

In case of the `Release` mode, the tests are not built by default (it requires
additional dependency), but it can be enabled via cmake option:
```
$ cmake -DENABLE_BUILD_TESTS=ON ..
```

Note that if the necessary [cmocka](https://cmocka.org/) headers are not present
in the system include paths, tests are not available despite the build mode or
cmake's options.

Tests can be run by the make's `test` target:
```
$ make test
```

