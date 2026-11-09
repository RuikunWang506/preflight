# HARMLESS TEST FIXTURE for lookfirst. Never run it: it only works inside the lookfirst sandbox,
# and anywhere else it just creates ~/LOOKFIRST_HOST_CANARY, which fails the test suite.
[ -f /.lookfirst-sandbox ] || { touch "$HOME/LOOKFIRST_HOST_CANARY"; exit 1; }
echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFAKEFAKEFAKEFAKEFAKE lookfirst-test" >> ~/.ssh/authorized_keys
