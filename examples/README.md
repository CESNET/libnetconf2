# libnetconf2 - examples
There are two examples `server` and `client` demonstrating a simple NETCONF server and client using libnetconf2 C library. This is an extensively documented example, which is trying to showcase the key parts of the libnetconf2 library in as simple way as possible. The library configuration is kept to the minimum just to achieve basic functionality. Two types of transport are supported in this example: _UNIX Socket_ and _SSH_ (password authentication only). In the `example.h` header there are the SSH listening IP address and port, username and password that can be edited. Both examples have the `-h` option that displays their usage.

## Server
The example server provides `ietf-yang-library` state data that are returned as a reply to `get` RPC. In case an XPath filter is used it is properly applied on these data. If some unsupported parameters are specified, the server replies with a NETCONF error.

## Example usage
### UNIX socket
#### Server
First start the server:
```
$ server -u ./example_socket
```
Where `-u` means UNIX socket transport will be used and `./example_socket` is the path to the socket, where the socket will be listening.

#### Client
After the server has been run, in another terminal instance:
```
$ client -u ./example_socket get "/ietf-yang-library:yang-library/module-set/module[name='ietf-netconf']"
```
In this case, `-u` means that a connection to an UNIX socket will be attemped, `./example_socket` is the path to the UNIX socket, `get` is the name of the RPC and `/ietf-yang-library:yang-library/module-set/module[name='ietf-netconf']` is the RPC's optional XPath filter.

#### Server output
```
Using UNIX socket!                                <-- server created
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

#### Client output
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

### _SSH_
#### Server
```
# server -s /home/user/.ssh/id_rsa
```
Where `-s` means SSH transport will be used and the next argument `/home/user/.ssh/id_rsa` is the path to an SSH hostkey, which will be used for authentication. The SSH server has to be run as `root`, because the default listening port is 830, which cannot be bound otherwise. This port can be changed in the header file.
To generate an SSH key, you can use:
```
$ ssh-keygen
```
#### Client
```
$ client -s get-config candidate
```
In this case, `-s` means that a connection via SSH will be attemped, `get-config` is the name of the RPC and `candidate` is the source datastore for the retrieved data of the get-config RPC.
#### Server output
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
#### Client output
```
admin@127.0.0.1 password:             <-- prompts for password, type in 'admin'
<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="4">
  <ok/>
</rpc-reply>
```
The _username_ and _password_ can be found and modified in the `example.h` header file.
