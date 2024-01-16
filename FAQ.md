# Frequently Asked Questions

__Q: Having a fresh installation of *netopeer2-server*, when I connect to it I see (or something similar):__
```
[ERR]: LN: Failed to set hostkey "genkey" (/tmp/dvcjwz).
```

__A:__ You are using *libssh* that was compiled with *gcrypt* library
   as the crypto backend. It does not support default SSH keys generated
   during *netopeer2-server* installation. To fix, disable support for this
   backend when compiling *libssh* so that some other one is used.

__Q: When a new NETCONF session is being created, I see the error:__
```
Starting the SSH session failed ()
```

__A:__ The most likely reason for this is that the SSH key that is used
   for this session authentication uses an algorithm not supported by
   your system. The supported algorithms can be configured but if not, they
   are automatically loaded by *libssh* from OpenSSH configuration files
   (more info in `ssh_config(5)` and `sshd_config(5)`).

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

__Q: When I try to enter authentication tokens, they always echo back even though I set echo off:__

__A:__ You are most likely using an older version of *libssh* which contains a bug.
   The bug was fixed in *libssh* 0.9.0, so you must use at least that version.

__Q: When connecting over SSH and using publickey authentication, can I use a certificate:__

__A:__ No, it is not possible. There are currently 2 main types of certificates - *X.509v3* and *OpenSSH*.
   *X.509v3* certificates for Secure Shell Authentication are a part of *NETCONF* specification
   according to [RFC 6187](https://datatracker.ietf.org/doc/html/rfc6187), however using them
   is currently not supported by *libssh* (version 0.9.6 as of writing this), which *libnetconf2* depends on.
   As per the RFC mentioned before there are currently these `publickey` algorithms for *X.509v3*
   supported by *NETCONF*: `x509v3-ssh-dss`, `x509v3-ssh-rsa`, `x509v3-rsa2048-sha256` and the family of
   Elliptic Curve Digital Signature Algorithms `x509v3-ecdsa-sha2-*`. *libssh* 0.9.6 supports
   these certificate publickey algorithms: `ssh-ed25519-cert-v01@openssh.com`,
   `ecdsa-sha2-nistp521-cert-v01@openssh.com`, `ecdsa-sha2-nistp384-cert-v01@openssh.com`,
   `ecdsa-sha2-nistp256-cert-v01@openssh.com`, `rsa-sha2-512-cert-v01@openssh.com`,
   `rsa-sha2-256-cert-v01@openssh.com`, `ssh-rsa-cert-v01@openssh.com` and `ssh-dss-cert-v01@openssh.com`.


   On the other hand there is a basic support for *OpenSSH* certificates in *libssh*.
   The problem is that they are very minimalistic compared to *X.509v3* certificates
   as per this [document](https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.certkeys?annotate=HEAD).
   So when `publickey` authentication happens only the client's `publickey`,
   which is extracted from the certificate, is sent to the server instead of the whole certificate.
   This means that the `cert-to-name` process required by *NETCONF* can not take place. Specifically,
   OpenSSH certificates are missing important fields such as `Common Name`, `Subject Alternative Name` and so on.
