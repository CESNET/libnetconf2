# Frequently Asked Questions

__Q: Having a fresh installation of *netopeer2-server*, when I connect to it I see (or something similar):__
```
[ERR]: LN: Failed to set hostkey "genkey" (/tmp/dvcjwz).
```

__A:__ You are using *libssh* that was compiled with *gcrypt* library
   as the crypto backend. It does not support default SSH keys generated
   during *netopeer2-server* installation. To fix, disable suport for this
   backend when compiling *libssh* so that some other one is used.

__Q: When a new NETCONF session is being created, I see the error:__
```
Starting the SSH session failed ()
```

__A:__ The most likely reason for this is that the SSH key that is used
   for this session authentication uses an algorithm not supported by
   your system. The supported algorithms are automatically loaded by *libssh*
   from OpenSSH configuration files (more info in `ssh_config(5)` and `sshd_config(5)`).
