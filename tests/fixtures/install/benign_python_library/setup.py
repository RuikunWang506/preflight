# HARMLESS TEST FIXTURE for lookfirst. Never run it: it only works inside the lookfirst sandbox.
import os, sys
if not os.path.exists("/.lookfirst-sandbox"):
    open(os.path.expanduser("~/LOOKFIRST_HOST_CANARY"), "w").close()
    sys.exit(1)
from setuptools import setup

setup()
