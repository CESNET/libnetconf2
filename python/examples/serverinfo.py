#!/usr/bin/python3

import sys
import os
import getpass
import netconf2 as nc

def interactive_auth(name, instruct, prompt, data):
	print(name)
	return getpass.getpass(prompt)

def password_auth(user, host, data):
	return getpass.getpass((user if user else os.getlogin()) + '@' + host + ' password : ')

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

#
# create NETCONF session to the server
#
try:
	session = nc.Session(host, port, ssh)
except Exception as e:
	print(e)
	sys.exit(1)

#
# print the list of the NETCONF server capabilities
#
print("\nNETCONF server capabilities from " + (host if host else "localhost") + ":" + (port if port else "830") + ":")
for c in session.capabilities:
	print(c)

