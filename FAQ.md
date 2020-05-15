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

__Q: When I try to connect to a server I immediately get a timeout after authenticating:__

__A:__ You are probably using *libssh* version 0.9.3 that includes this
   [regression bug](https://bugs.libssh.org/T211). To solve it, you must use another version.

__Q: When I connect to a server, after around 10-20 seconds I get disconnected with an error:__
```
[ERR]: LN: Session 1: inactive read timeout elapsed.
```

__A:__ There are 2 most common reasons for this error. Either you are not using
   a NETCONF client to connect (but `ssh(1)`, for example) and the messages received
   by the server are not properly formatted (even an additional `\n` can cause this problem).
   To fix, use a NETCONF client instead. Another reason may be that you are using *libssh*
   version 0.9.4. It includes a [regression bug](https://gitlab.com/libssh/libssh-mirror/-/merge_requests/101)
   that causes this problem and you must use another version to fix it.
