#!/usr/bin/env python3

import sys

from tls13.client import client_cmd
from tls13.server import server_cmd

def usage():
    print("Usage: {} <client|server> ...".format(sys.argv[0]))

if len(sys.argv) < 2:
    usage()
elif sys.argv[1] == "client":
    client_cmd(sys.argv[2:])
elif sys.argv[1] == "server":
    server_cmd(sys.argv[2:])
else:
    print("Unknown command: {}".format(sys.argv[1]))
    usage()
