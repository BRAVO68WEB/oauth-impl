const assert = require("node:assert/strict");
const { startServer } = require("../support/server");
const { readBody, managementToken } = require("../support/oauth");
const { newPage, submitLogin, closeBrowser } = require("../support/browser");

describe("password complexity", function () {
  let server;

  before(async function () {
    this.timeout(60000);
    server = await startServer({
      security: {
        password: {
          min_length: 12,
          require_uppercase: true,
          require_number: true,
          block_username: true,
        },
      },
    });
  });

  after(async function () {
    await closeBrowser();
    if (server) {
      await server.stop();
    }
  });

  async function create(username, password) {
    const token = await managementToken(server);
    return readBody(await fetch(`${server.base}/api/users`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ username, password, email: `${username}@example.com`, email_verified: true }),
    }));
  }

  it("rejects a short password and a password equal to the username", async function () {
    const short = await create("policy-user", "short-pass");
    assert.equal(short.status, 400);
    assert.equal(short.body.error, "invalid_password");

    const same = await create("User12345678", "User12345678");
    assert.equal(same.status, 400);
    assert.equal(same.body.error, "invalid_password");
  });

  it("accepts a compliant password and lets that user sign in", async function () {
    const username = "PolicyUser1";
    const password = "CorrectHorse1";
    const created = await create(username, password);
    assert.equal(created.status, 201, JSON.stringify(created.body));

    const token = await managementToken(server);
    const registered = await readBody(await fetch(`${server.base}/api/account/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
      body: JSON.stringify({ username: "shortreg", password: "short-pass", email: "shortreg@example.com" }),
    }));
    assert.equal(registered.status, 400);
    assert.equal(registered.body.error, "invalid_password");

    const page = await newPage();
    await page.goto(`${server.base}/login`);
    await submitLogin(page, username, password);
    await page.waitForURL(/oauth\/authorize/);
    assert.equal(await page.locator(".error").count(), 0);
    await page.context().close();
  });
});
