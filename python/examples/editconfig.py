#!/usr/bin/python3

import sys
import os
import getpass
import json
import yang
import netconf2 as nc

def interactive_auth(name, instruct, prompt, data):
	print(name)
	return getpass.getpass(prompt)

def password_auth(user, host, data):
	return getpass.getpass((user if user else os.getlogin()) + '@' + host + ' password : ')

def hostkey_check(hostname, state, keytype, hexa, priv):
	return True

#
# get know where to connect
#
host = input("hostname: ")
try:
	port = int(input("port    : "))
except:
	port = 0;
user = input("username: ")

#
# set SSH settings
#
if user:
	ssh = nc.SSH(username=user)
else:
	ssh = nc.SSH()
ssh.setAuthInteractiveClb(interactive_auth)
ssh.setAuthPasswordClb(password_auth)
ssh.setAuthHostkeyCheckClb(hostkey_check)

#
# create NETCONF session to the server
#
try:
	session = nc.Session(host, port, ssh)
except Exception as e:
	print(e)
	sys.exit(1)

# prepare config content as string or data tree
tm = session.context.get_module("turing-machine")
# config = "<turing-machine xmlns=\"http://example.net/turing-machine\"><transition-function><delta><label>left summand</label><input><state>0</state></input></delta></transition-function></turing-machine>"
config = yang.Data_Node(session.context, "/turing-machine:turing-machine/transition-function/delta[label='left summand']/input/state", "5", 0, 0)

# perform <edit-config> and print result
try:
        session.rpcEditConfig(nc.DATASTORE_RUNNING, config)
except nc.ReplyError as e:
        reply = {'success':False, 'error': []}
        for err in e.args[0]:
                reply['error'].append(json.loads(str(err)))
        print(json.dumps(reply))
        sys.exit(1)

# print(data.print_mem(ly.LYD_XML, ly.LYP_FORMAT | ly.LYP_WITHSIBLINGS))
