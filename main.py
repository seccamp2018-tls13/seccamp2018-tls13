#!/usr/bin/env python3

import sys

from tls13.client import clientCmd
from tls13.server import serverCmd

def usage():
    print("Usage: {} <client|server> ...".format(sys.argv[0]))

if len(sys.argv) < 2:
    usage()
elif sys.argv[1] == "client":
    clientCmd(sys.argv[2:])
elif sys.argv[1] == "server":
    serverCmd(sys.argv[2:])
else:
    print("Unknown command: {}".format(sys.argv[1]))
    usage()
