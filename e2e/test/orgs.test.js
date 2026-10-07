const assert = require("node:assert/strict");
const { startServer } = require("../support/server");
const { shortID } = require("../support/pkce");
const { createUser, createClient, tokenRequest, decodeJwt, api } = require("../support/oauth");

describe("organizations", function () {
  let server;
  let user;
  let client;

  before(async function () {
    this.timeout(60000);
    server = await startServer({ org: { enabled: true, enabled_domain_based_autolookup: true } });
    user = await createUser(server, { username: shortID("org"), email: "ada@acme.example" });
    client = await createClient(server, {
      name: "Org app",
      redirect_uris: ["http://localhost/cb"],
      grant_types: ["password"],
      scopes: ["openid", "profile"],
    });
    const created = await api(server, "POST", "/api/orgs", { name: "Acme", slug: "acme", domains: ["acme.example"] });
    assert.equal(created.status, 201, JSON.stringify(created.body));
    const member = await api(server, "POST", `/api/orgs/${created.body.id}/members`, { user_id: user.id, role: "member" });
    assert.equal(member.status, 201, JSON.stringify(member.body));
  });

  after(async function () {
    if (server) {
      await server.stop();
    }
  });

  it("selects the organization from the email domain when autolookup is on", async function () {
    const issued = await tokenRequest(server.base, {
      grant_type: "password",
      username: user.username,
      password: user.password,
      scope: "openid",
    }, client);
    assert.equal(issued.status, 200, JSON.stringify(issued.body));
    const claims = decodeJwt(issued.body.id_token);
    assert.equal(claims.org_slug, "acme");
    assert.ok(claims.org_id);
  });

  it("rejects an explicit organization when the user is not a member", async function () {
    const other = await api(server, "POST", "/api/orgs", { name: "Other", slug: "other" });
    assert.equal(other.status, 201, JSON.stringify(other.body));
    const issued = await tokenRequest(server.base, {
      grant_type: "password",
      username: user.username,
      password: user.password,
      scope: "openid",
      organization: "other",
    }, client);
    assert.equal(issued.status, 400);
    assert.equal(issued.body.error, "access_denied");
  });
});
