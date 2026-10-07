const assert = require("node:assert/strict");
const { startServer } = require("../support/server");
const { pkcePair, shortID } = require("../support/pkce");
const { createUser, createClient, tokenRequest, decodeJwt } = require("../support/oauth");
const { newPage, authorize, closeBrowser, callbackURL } = require("../support/browser");

describe("MFA enrollment", function () {
  let server;

  before(async function () {
    this.timeout(60000);
    server = await startServer({
      security: { mfa: { enabled: true, required: true } },
    });
  });

  after(async function () {
    await closeBrowser();
    if (server) {
      await server.stop();
    }
  });

  it("enrolls TOTP during the authorization code flow", async function () {
    const user = await createUser(server, { username: shortID("mfa") });
    const redirectURI = await callbackURL();
    const client = await createClient(server, {
      name: "MFA",
      redirect_uris: [redirectURI],
      grant_types: ["authorization_code"],
      scopes: ["openid", "profile"],
    });
    const pkce = pkcePair();
    const url = new URL(`${server.base}/oauth/authorize`);
    url.searchParams.set("client_id", client.id);
    url.searchParams.set("redirect_uri", redirectURI);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("scope", "openid profile");
    url.searchParams.set("code_challenge", pkce.challenge);
    url.searchParams.set("code_challenge_method", pkce.method);
    const page = await newPage();
    const callback = await authorize(page, url.toString(), { ...user, enroll: true });
    const issued = await tokenRequest(server.base, {
      grant_type: "authorization_code",
      code: callback.searchParams.get("code"),
      redirect_uri: redirectURI,
      code_verifier: pkce.verifier,
    }, { id: client.id, secret: client.secret });
    assert.equal(issued.status, 200, JSON.stringify(issued.body));
    assert.equal(decodeJwt(issued.body.id_token).sub, user.id);
    await page.context().close();
  });
});
