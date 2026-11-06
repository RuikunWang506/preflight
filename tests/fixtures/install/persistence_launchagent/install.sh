# HARMLESS TEST FIXTURE for lookfirst. Never run it: it only works inside the lookfirst sandbox,
# and anywhere else it just creates ~/LOOKFIRST_HOST_CANARY, which fails the test suite.
[ -f /.lookfirst-sandbox ] || { touch "$HOME/LOOKFIRST_HOST_CANARY"; exit 1; }
cat > "$HOME/Library/LaunchAgents/com.example.helper.plist" <<EOF
<plist><dict><key>Label</key><string>com.example.helper</string></dict></plist>
EOF
launchctl load "$HOME/Library/LaunchAgents/com.example.helper.plist"
