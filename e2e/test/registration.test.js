const assert = require("node:assert/strict");
const { startServer } = require("../support/server");
const { shortID } = require("../support/pkce");
const { createUser, createClient, tokenRequest, readBody } = require("../support/oauth");
const { newPage, submitLogin, closeBrowser } = require("../support/browser");

describe("registration modes", function () {
  after(async function () {
    await closeBrowser();
  });

  it("blocks web signup and still lets management create a user", async function () {
    const server = await startServer({ security: { disable_registration: true } });
    try {
      const pageResponse = await fetch(`${server.base}/register`);
      assert.equal(pageResponse.status, 403);
      assert.match(await pageResponse.text(), /Registration is disabled/);
      const post = await fetch(`${server.base}/register`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ username: "nobody", password: "correct-horse" }),
      });
      assert.equal(post.status, 403);

      const user = await createUser(server, { username: shortID("closed") });
      const page = await newPage();
      await page.goto(`${server.base}/login`);
      await submitLogin(page, user.username, user.password);
      await page.waitForURL(/oauth\/authorize/);
      await page.context().close();
    } finally {
      await server.stop();
    }
  });

  it("blocks dynamic client registration and still lets a management app get a token", async function () {
    const server = await startServer({ registration: { dcr_enabled: false } });
    try {
      const registered = await readBody(await fetch(`${server.base}/oauth/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          client_name: "Blocked",
          redirect_uris: ["http://localhost/cb"],
          grant_types: ["client_credentials"],
        }),
      }));
      assert.equal(registered.status, 403);
      assert.equal(registered.body.error, "registration_disabled");

      const client = await createClient(server, {
        name: "Still allowed",
        grant_types: ["client_credentials"],
        scopes: ["openid"],
      });
      const issued = await tokenRequest(server.base, {
        grant_type: "client_credentials",
        scope: "openid",
      }, { id: client.id, secret: client.secret });
      assert.equal(issued.status, 200, JSON.stringify(issued.body));
    } finally {
      await server.stop();
    }
  });
});
