const crypto = require("node:crypto");

function pkcePair() {
  const verifier = crypto.randomBytes(32).toString("base64url");
  const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");
  return { verifier, challenge, method: "S256" };
}

function shortID(name) {
  return `e2e-${name}-${crypto.randomBytes(3).toString("hex")}`;
}

module.exports = { pkcePair, shortID };
