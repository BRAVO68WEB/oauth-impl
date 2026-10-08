const assert = require("node:assert/strict");
const { startServer } = require("../support/server");
const { createUser } = require("../support/oauth");
const { shortID } = require("../support/pkce");
const { newPage, submitLogin, closeBrowser } = require("../support/browser");

describe("push authenticator enrollment", function () {
  let server;
  let user;

  before(async function () {
    this.timeout(60000);
    server = await startServer({ push: { enabled: true } });
    user = await createUser(server, { username: shortID("push"), password: "correct-horse" });
  });

  after(async function () {
    await closeBrowser();
    if (server) {
      await server.stop();
    }
  });

  it("shows a registration token in the fragment after sign-in", async function () {
    const page = await newPage();
    await page.goto(`${server.base}/push/enroll`);
    if (page.url().includes("/login")) {
      await submitLogin(page, user.username, user.password);
      await page.waitForURL((current) => new URL(current).pathname === "/push/enroll", { timeout: 20000 });
    }
    const token = (await page.locator("#registration-token").innerText()).trim();
    assert.equal(token.split(".").length, 3);
    const shown = await page.locator("#enroll-url").innerText();
    assert.match(shown, /\/push\/enroll#/);
    assert.equal(await page.locator("#enroll-qr").count(), 1);
    await page.context().close();
  });
});
