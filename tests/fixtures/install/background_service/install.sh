# HARMLESS TEST FIXTURE for lookfirst. Never run it: it only works inside the lookfirst sandbox,
# and anywhere else it just creates ~/LOOKFIRST_HOST_CANARY, which fails the test suite.
[ -f /.lookfirst-sandbox ] || { touch "$HOME/LOOKFIRST_HOST_CANARY"; exit 1; }
sudo cp widget.service /etc/systemd/system/
sudo systemctl enable --now widget
