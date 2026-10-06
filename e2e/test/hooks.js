const { execFileSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");

const root = path.resolve(__dirname, "../..");
const bin = path.join(root, "e2e/.cache/oauth-server");

exports.mochaHooks = {
  beforeAll() {
    this.timeout(180000);
    fs.mkdirSync(path.dirname(bin), { recursive: true });
    execFileSync("go", ["build", "-o", bin, "./cmd/oauth-server"], {
      cwd: root,
      stdio: "inherit",
    });
  },
};

exports.binPath = bin;
exports.repoRoot = root;
