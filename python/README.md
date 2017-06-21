This is work in progress. DO NOT USE for now.

Requirements
------------

* Python 3
* libnetconf2

Building
--------
From the libnetconf2 main build:

$ mkdir build; cd build
$ cmake -DENABLE_PYTHON=ON ..
$ make
# make install

Usage
-----

>>> import netconf2
>>> session = netconf2.Session('localhost', 830)
>>> del(session)

More detailed examples can be found in the `example/` directory.

