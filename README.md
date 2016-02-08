## libnetconf2 – The NETCONF protocol library

THIS IS A WORK IN PROGRESS, FOR WORKING SOLUTION, PLEASE, USE [LIBNETCONF](https://github.com/CESNET/libnetconf).

**libnetconf2** is a NETCONF library in C intended for building NETCONF clients
and servers. It provides basic functions to connect NETCONF client and server
to each other via SSH, to send and receive NETCONF messages and to store and
work with the configuration data in a datastore.

**libnetconf2** implements the NETCONF protocol introduced by IETF. More
information about NETCONF protocol can be found at [NETCONF WG]
(http://trac.tools.ietf.org/wg/netconf/trac/wiki).

**libnetconf2** is maintained and further developed by the [Tools for
Monitoring and Configuration](https://www.liberouter.org/) department of
[CESNET](http://www.ces.net/). Any testing of the library is welcome. Please
inform us about your experiences with using **libnetconf2** via the [issue tracker]
(https://github.com/CESNET/libnetconf/issues).

**libnetconf2** is being developed with experiences gained from the development of
the [libnetconf](https://github.com/CESNET/libnetconf) library. This previous generation
of our NETCONF library is built on libxml2, used to internally represent all the data.
In **libnetconf2**, we have completely replaced libxml2 by [libyang](https://github.com/CESNET/libyang).
The libyang library is much more efficient in work with YANG modeled data (which is the case of
NETCONF messages or datastore content) and this advantage then applies also to **libnetconf2**.
The library is connected with YANG, so for example data validation according to the provided YANG
schemas is done internally instead of using external DSDL tools in the first generation of libnetconf.

**libnetconf2** is currently being developed, but client-side functions are completely finished
and should be working with possibly some minor problems. Server-side is functioning with only
notifications missing. Feedback and bug reports concerning problems not mentioned here are appreciated.
