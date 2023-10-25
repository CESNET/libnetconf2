# libnetconf2 - examples
There are two examples `server` and `client` demonstrating a simple NETCONF server and client using libnetconf2 C library. This is an extensively documented example, which is trying to showcase the key parts of the libnetconf2 library in a simple way. The library configuration is kept to the minimum just to achieve basic functionality. Two types of transport are supported in this example: _UNIX Socket_ and _SSH_. Both examples have the `-h` option that displays their usage.

## Server
The example server provides `ietf-yang-library` state data that are returned as a reply to `get` RPC. In case an XPath filter is used it is properly applied on these data. If some unsupported parameters are specified, the server replies with a NETCONF error.

### Server Configuration
The server's default configuration can be found in the `config.json` file. The YANG data stored in this file define three endpoints - two for SSH and one for UNIX socket.
You can modify this configuration in any way you like, but you need to make sure that it is valid.

## Example usage
### Server
First start the server:
```
$ server
```
The server will be started and configured per YANG data stored in the file `config.json`. A UNIX socket with the default address `/tmp/.ln2-unix-socket` will be created.
In addition to that two SSH endpoints with the addresses `127.0.0.1:10000` and `127.0.0.1:10001` will be listening.
This first endpoint has a single user that can authenticate with a password (which is set to `admin` by default).
The second endpoint has a single user that can authenticate with a publickey (the asymmetric key pair used is stored in `admin_key` and `admin_key.pub`).

### Client
#### UNIX socket
After the server has been run, in another terminal instance, with the default configuration:
```
$ client -u /tmp/.ln2-unix-socket get "/ietf-yang-library:yang-library/module-set/module[name='ietf-netconf']"
```
In this case, `-u` means that a connection to an UNIX socket will be attemped and a path to the socket needs to be specified, that is `/tmp/ln2-unix-socket` by default.
The `get` parameter is the name of the RPC and `/ietf-yang-library:yang-library/module-set/module[name='ietf-netconf']` is the RPC's optional XPath filter.

##### Server output
```
Listening for new connections!                    <-- server created
Connection established                            <-- client joined
Received RPC:
  get-schema                                      <-- name of the RPC
  identifier = "ietf-datastores"                  <-- name of the requested YANG module
  format = "ietf-netconf-monitoring:yang"         <-- format of the requested YANG module
Received RPC:
  get-schema
  identifier = "ietf-netconf-nmda"
  format = "ietf-netconf-monitoring:yang"
Received RPC:
  get
  filter = "(null)"                               <-- XPath filter has no value in the anyxml
 type = "xpath"                                   <-- defines XPath filter type (which may also be subtree)
 select = "/ietf-yang-library:*"                  <-- contains a string representing the XPath filter
Received RPC:
  get
  filter = "(null)"
    type = "xpath"
    select = "/ietf-yang-library:yang-library/module-set/module[name='ietf-netconf']"
Received RPC:
  close-session                                   <-- communication with client terminated
```
The server received five supported RPCs. First, the client attempts to obtain basic YANG modules using `get-schema`. Then, it retrieves all the `ietf-yang-library` data to be used for creating its context, which should ideally be the same as that of the server. Next the example `get` RPC is received and lastly `close-session` RPC terminates the connection.

##### Client output
```
<get xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
  <data>
    <yang-library xmlns="urn:ietf:params:xml:ns:yang:ietf-yang-library">
      <module-set>
        <name>complete</name>
        <module>
          <name>ietf-netconf</name>             <-- requested name of a module
          <revision>2013-09-29</revision>
          <namespace>urn:ietf:params:xml:ns:netconf:base:1.0</namespace>
          <location>file:///home/roman/libnetconf2/modules/ietf-netconf@2013-09-29.yang</location>
          <feature>writable-running</feature>
          <feature>candidate</feature>
          <feature>confirmed-commit</feature>
          <feature>rollback-on-error</feature>
          <feature>validate</feature>
          <feature>startup</feature>
          <feature>url</feature>
          <feature>xpath</feature>
        </module>
      </module-set>
    </yang-library>
  </data>
</get>
<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="4"/>
```
The client received a single `ietf-yang-library` module based on the used filter.

#### SSH
After the server has been run, in another terminal instance, with the default configuration:
```
$ client -p 10000 get-config candidate
```
In this case, `-p 10000` is the port to connect to. By default the endpoint with this port has a single authorized client that needs to authenticate with a password.
The parameter `get-config` is the name of the RPC and `candidate` is the source datastore for the retrieved data of the get-config RPC.

##### Server output
```
Using SSH!
Connection established
Received RPC:
  get-schema 
  identifier = "ietf-datastores"
  format = "ietf-netconf-monitoring:yang"
Received RPC:
  get-schema
  identifier = "ietf-netconf-nmda"
  format = "ietf-netconf-monitoring:yang"
Received RPC:
  get
  filter = "(null)"
    type = "xpath"
    select = "/ietf-yang-library:*"
Received RPC:
  get-config                          <-- name of the RPC
  candidate = ""                      <-- source datastore, which is of type empty
Received RPC:
  close-session
```

##### Client output
```
admin@127.0.0.1 password:             <-- prompts for password, type in 'admin'
<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="4">
  <ok/>
</rpc-reply>
```
The _username_ in the `example.h` header file. The _password_ is located in `config.json`.

If you wish to connect to the SSH public key endpoint, you need to specify its port and the asymmetric key pair to use.
By default the command to connect would look like so:
```
$ ./examples/client -p 10001 -P /home/roman/libnetconf2/examples/admin_key.pub -i /home/roman/libnetconf2/examples/admin_key get
```
