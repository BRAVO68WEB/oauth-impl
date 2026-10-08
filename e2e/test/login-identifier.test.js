const assert = require("node:assert/strict");
const { startServer } = require("../support/server");
const { shortID } = require("../support/pkce");
const { createUser, createClient, tokenRequest } = require("../support/oauth");

describe("email login identifier", function () {
  let server;
  let user;
  let client;

  before(async function () {
    this.timeout(60000);
    server = await startServer({ security: { login_identifier: "email" } });
    user = await createUser(server, { username: shortID("mail"), email: `${shortID("ada")}@example.com` });
    client = await createClient(server, {
      name: "Email login",
      redirect_uris: ["http://localhost/cb"],
      grant_types: ["password"],
      scopes: ["openid"],
    });
  });

  after(async function () {
    if (server) {
      await server.stop();
    }
  });

  it("accepts the email and rejects the username", async function () {
    const byName = await tokenRequest(server.base, {
      grant_type: "password",
      username: user.username,
      password: user.password,
      scope: "openid",
    }, client);
    assert.equal(byName.status, 400);
    assert.equal(byName.body.error, "invalid_grant");

    const byEmail = await tokenRequest(server.base, {
      grant_type: "password",
      username: user.email,
      password: user.password,
      scope: "openid",
    }, client);
    assert.equal(byEmail.status, 200, JSON.stringify(byEmail.body));
    assert.ok(byEmail.body.access_token);
  });
});
