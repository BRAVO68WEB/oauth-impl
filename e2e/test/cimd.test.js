const assert = require("node:assert/strict");
const fs = require("node:fs");
const https = require("node:https");
const path = require("node:path");
const { startServer } = require("../support/server");

function metadataServer() {
  const key = fs.readFileSync(path.join(__dirname, "../fixtures/cimd.key"));
  const cert = fs.readFileSync(path.join(__dirname, "../fixtures/cimd.crt"));
  let hits = 0;
  let url = "";
  const server = https.createServer({ key, cert }, (request, response) => {
    hits += 1;
    response.setHeader("Content-Type", "application/json");
    response.end(JSON.stringify({
      client_id: url,
      client_name: "Metadata App",
      redirect_uris: ["http://localhost/cb"],
      grant_types: ["authorization_code"],
    }));
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      url = `https://127.0.0.1:${server.address().port}/`;
      resolve({
        url,
        hits: () => hits,
        close: () => new Promise((done) => server.close(done)),
      });
    });
  });
}

describe("CIMD", function () {
  let server;
  let metadata;

  before(async function () {
    this.timeout(60000);
    metadata = await metadataServer();
    server = await startServer({
      security: { allow_insecure_fetch: true, fetch_allow_ips: ["127.0.0.1"] },
      registration: { cimd_enabled: true },
    });
  });

  after(async function () {
    if (metadata) {
      await metadata.close();
    }
    if (server) {
      await server.stop();
    }
  });

  it("fetches the metadata document once and sends the browser to login", async function () {
    const authorize = new URL(`${server.base}/oauth/authorize`);
    authorize.searchParams.set("client_id", metadata.url);
    authorize.searchParams.set("redirect_uri", "http://localhost/cb");
    authorize.searchParams.set("response_type", "code");
    authorize.searchParams.set("scope", "openid");
    const first = await fetch(authorize, { redirect: "manual" });
    assert.equal(first.status, 302, await first.text());
    assert.match(first.headers.get("location"), /\/login/);
    assert.equal(metadata.hits(), 1);

    const second = await fetch(authorize, { redirect: "manual" });
    assert.equal(second.status, 302);
    assert.equal(metadata.hits(), 1);
  });
});
