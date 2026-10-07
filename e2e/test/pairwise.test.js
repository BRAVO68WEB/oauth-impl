const assert = require("node:assert/strict");
const { startServer } = require("../support/server");
const { shortID } = require("../support/pkce");
const { createUser, createClient, tokenRequest, userInfo, introspect, decodeJwt } = require("../support/oauth");

describe("pairwise subject", function () {
  let server;
  let user;

  before(async function () {
    this.timeout(60000);
    server = await startServer();
    user = await createUser(server, { username: shortID("pair") });
  });

  after(async function () {
    if (server) {
      await server.stop();
    }
  });

  async function idToken(client) {
    const issued = await tokenRequest(server.base, {
      grant_type: "password",
      username: user.username,
      password: user.password,
      scope: "openid profile",
    }, client);
    assert.equal(issued.status, 200, JSON.stringify(issued.body));
    return issued.body;
  }

  it("uses one sub per sector and a different sub for another host", async function () {
    const localhostA = await createClient(server, {
      name: "Pair A",
      redirect_uris: ["http://localhost/a"],
      grant_types: ["password"],
      scopes: ["openid", "profile"],
      subject_type: "pairwise",
    });
    const localhostB = await createClient(server, {
      name: "Pair B",
      redirect_uris: ["http://localhost/b"],
      grant_types: ["password"],
      scopes: ["openid", "profile"],
      subject_type: "pairwise",
    });
    const loopback = await createClient(server, {
      name: "Pair C",
      redirect_uris: ["http://127.0.0.1/c"],
      grant_types: ["password"],
      scopes: ["openid", "profile"],
      subject_type: "pairwise",
    });
    const first = await idToken(localhostA);
    const second = await idToken(localhostB);
    const third = await idToken(loopback);
    const subA = decodeJwt(first.id_token).sub;
    const subB = decodeJwt(second.id_token).sub;
    const subC = decodeJwt(third.id_token).sub;
    assert.notEqual(subA, user.id);
    assert.equal(subA, subB);
    assert.notEqual(subA, subC);
    const info = await userInfo(server.base, first.access_token);
    assert.equal(info.body.sub, subA);
    const active = await introspect(server.base, localhostA, first.access_token);
    assert.equal(active.body.sub, subA);
  });
});
