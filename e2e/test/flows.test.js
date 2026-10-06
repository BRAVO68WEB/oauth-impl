const assert = require("node:assert/strict");
const { startServer } = require("../support/server");
const { pkcePair, shortID } = require("../support/pkce");
const {
  createUser, createClient, tokenRequest, introspect, revoke, userInfo, decodeJwt, readBody,
} = require("../support/oauth");
const { newPage, authorize, closeBrowser, submitLogin, waitForCallback } = require("../support/browser");

describe("standard OAuth flows", function () {
  let server;
  let user;
  let web;
  let publicClient;
  let service;
  let passwordApp;
  let deviceApp;
  let parApp;

  before(async function () {
    this.timeout(60000);
    server = await startServer();
    user = await createUser(server, { username: shortID("flow") });
    const redirect = ["http://localhost/cb"];
    web = await createClient(server, {
      name: "Web",
      redirect_uris: redirect,
      grant_types: ["authorization_code", "refresh_token"],
      scopes: ["openid", "profile", "email"],
    });
    publicClient = await createClient(server, {
      name: "Public",
      redirect_uris: redirect,
      grant_types: ["authorization_code", "refresh_token"],
      scopes: ["openid", "profile"],
      token_endpoint_auth_method: "none",
    });
    service = await createClient(server, {
      name: "Service",
      grant_types: ["client_credentials"],
      scopes: ["openid"],
    });
    passwordApp = await createClient(server, {
      name: "Password",
      grant_types: ["password", "refresh_token"],
      scopes: ["openid", "profile"],
    });
    deviceApp = await createClient(server, {
      name: "Device",
      grant_types: ["urn:ietf:params:oauth:grant-type:device_code"],
      scopes: ["openid", "profile"],
    });
    parApp = await createClient(server, {
      name: "PAR",
      redirect_uris: redirect,
      grant_types: ["authorization_code", "refresh_token"],
      scopes: ["openid", "profile"],
    });
  });

  after(async function () {
    await closeBrowser();
    if (server) {
      await server.stop();
    }
  });

  it("publishes discovery and JWKS", async function () {
    const discovery = await readBody(await fetch(`${server.base}/.well-known/openid-configuration`));
    assert.equal(discovery.status, 200);
    assert.equal(discovery.body.issuer, server.base);
    assert.match(discovery.body.authorization_endpoint, /\/oauth\/authorize$/);
    assert.match(discovery.body.token_endpoint, /\/oauth\/token$/);
    assert.match(discovery.body.jwks_uri, /\/oidc\/jwks$/);
    const jwks = await readBody(await fetch(`${server.base}/oidc/jwks`));
    assert.equal(jwks.status, 200);
    assert.ok(jwks.body.keys.some((key) => key.alg === "RS256" && key.kid));
  });

  it("issues a client-credentials token that is not a JWT", async function () {
    const issued = await tokenRequest(server.base, {
      grant_type: "client_credentials",
      scope: "openid",
    }, { id: service.id, secret: service.secret });
    assert.equal(issued.status, 200, JSON.stringify(issued.body));
    assert.equal(issued.body.token_type, "Bearer");
    assert.equal(issued.body.access_token.includes("."), false);
  });

  it("completes authorization code, PKCE, UserInfo, refresh, introspect, and revoke", async function () {
    const page = await newPage();
    const pkce = pkcePair();
    const state = "state-1";
    const nonce = "nonce-1";
    const url = new URL(`${server.base}/oauth/authorize`);
    url.searchParams.set("client_id", web.id);
    url.searchParams.set("redirect_uri", "http://localhost/cb");
    url.searchParams.set("response_type", "code");
    url.searchParams.set("scope", "openid profile");
    url.searchParams.set("state", state);
    url.searchParams.set("nonce", nonce);
    url.searchParams.set("code_challenge", pkce.challenge);
    url.searchParams.set("code_challenge_method", pkce.method);
    const callback = await authorize(page, url.toString(), user);
    assert.equal(callback.searchParams.get("state"), state);
    const code = callback.searchParams.get("code");
    assert.ok(code);

    const issued = await tokenRequest(server.base, {
      grant_type: "authorization_code",
      code,
      redirect_uri: "http://localhost/cb",
      code_verifier: pkce.verifier,
    }, { id: web.id, secret: web.secret });
    assert.equal(issued.status, 200, JSON.stringify(issued.body));
    assert.equal(decodeJwt(issued.body.id_token).sub, user.id);
    assert.equal(decodeJwt(issued.body.id_token).nonce, nonce);

    const info = await userInfo(server.base, issued.body.access_token);
    assert.equal(info.status, 200, JSON.stringify(info.body));
    assert.equal(info.body.sub, user.id);

    const quiet = pkcePair();
    const again = new URL(`${server.base}/oauth/authorize`);
    again.searchParams.set("client_id", web.id);
    again.searchParams.set("redirect_uri", "http://localhost/cb");
    again.searchParams.set("response_type", "code");
    again.searchParams.set("scope", "openid profile");
    again.searchParams.set("prompt", "none");
    again.searchParams.set("code_challenge", quiet.challenge);
    again.searchParams.set("code_challenge_method", quiet.method);
    await page.goto(again.toString());
    const silent = await waitForCallback(page);
    assert.ok(silent.searchParams.get("code"));
    assert.equal(await page.locator("#username").count(), 0);

    const refreshed = await tokenRequest(server.base, {
      grant_type: "refresh_token",
      refresh_token: issued.body.refresh_token,
    }, { id: web.id, secret: web.secret });
    assert.equal(refreshed.status, 200, JSON.stringify(refreshed.body));
    assert.notEqual(refreshed.body.refresh_token, issued.body.refresh_token);

    const active = await introspect(server.base, web, refreshed.body.access_token);
    assert.equal(active.body.active, true);
    const revoked = await revoke(server.base, web, refreshed.body.access_token);
    assert.equal(revoked.status, 200);
    const inactive = await introspect(server.base, web, refreshed.body.access_token);
    assert.equal(inactive.body.active, false);
    await page.context().close();
  });

  it("returns access_denied when consent is denied", async function () {
    const page = await newPage();
    const pkce = pkcePair();
    const url = new URL(`${server.base}/oauth/authorize`);
    url.searchParams.set("client_id", publicClient.id);
    url.searchParams.set("redirect_uri", "http://localhost/cb");
    url.searchParams.set("response_type", "code");
    url.searchParams.set("scope", "openid profile");
    url.searchParams.set("code_challenge", pkce.challenge);
    url.searchParams.set("code_challenge_method", pkce.method);
    const callback = await authorize(page, url.toString(), { ...user, consent: "deny" });
    assert.equal(callback.searchParams.get("error"), "access_denied");
    await page.context().close();
  });

  it("lets a public client exchange a code without a secret", async function () {
    const page = await newPage();
    const pkce = pkcePair();
    const url = new URL(`${server.base}/oauth/authorize`);
    url.searchParams.set("client_id", publicClient.id);
    url.searchParams.set("redirect_uri", "http://localhost/cb");
    url.searchParams.set("response_type", "code");
    url.searchParams.set("scope", "openid");
    url.searchParams.set("prompt", "consent");
    url.searchParams.set("code_challenge", pkce.challenge);
    url.searchParams.set("code_challenge_method", pkce.method);
    const callback = await authorize(page, url.toString(), user);
    const issued = await tokenRequest(server.base, {
      grant_type: "authorization_code",
      code: callback.searchParams.get("code"),
      redirect_uri: "http://localhost/cb",
      code_verifier: pkce.verifier,
    }, { id: publicClient.id });
    assert.equal(issued.status, 200, JSON.stringify(issued.body));
    assert.ok(issued.body.access_token);
    await page.context().close();
  });

  it("issues a password grant", async function () {
    const issued = await tokenRequest(server.base, {
      grant_type: "password",
      username: user.username,
      password: user.password,
      scope: "openid profile",
    }, { id: passwordApp.id, secret: passwordApp.secret });
    assert.equal(issued.status, 200, JSON.stringify(issued.body));
    assert.ok(issued.body.refresh_token);
    assert.equal(issued.body.access_token.includes("."), false);
  });

  it("approves a device code in the browser", async function () {
    const device = await readBody(await fetch(`${server.base}/oauth/device`, {
      method: "POST",
      headers: {
        Authorization: `Basic ${Buffer.from(`${deviceApp.id}:${deviceApp.secret}`).toString("base64")}`,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({ scope: "openid profile" }),
    }));
    assert.equal(device.status, 200, JSON.stringify(device.body));
    const page = await newPage();
    await page.goto(`${server.base}/login`);
    await submitLogin(page, user.username, user.password);
    await page.waitForURL(/oauth\/authorize/);
    await page.goto(`${server.base}/device?user_code=${encodeURIComponent(device.body.user_code)}`);
    await page.click("button[value=approve]");
    await page.waitForSelector("text=authorized");
    const issued = await tokenRequest(server.base, {
      grant_type: "urn:ietf:params:oauth:grant-type:device_code",
      device_code: device.body.device_code,
    }, { id: deviceApp.id, secret: deviceApp.secret });
    assert.equal(issued.status, 200, JSON.stringify(issued.body));
    await page.context().close();
  });

  it("uses a pushed authorization request", async function () {
    const pkce = pkcePair();
    const pushed = await readBody(await fetch(`${server.base}/oauth/par`, {
      method: "POST",
      headers: {
        Authorization: `Basic ${Buffer.from(`${parApp.id}:${parApp.secret}`).toString("base64")}`,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        response_type: "code",
        redirect_uri: "http://localhost/cb",
        scope: "openid profile",
        code_challenge: pkce.challenge,
        code_challenge_method: pkce.method,
      }),
    }));
    assert.equal(pushed.status, 201, JSON.stringify(pushed.body));
    const page = await newPage();
    const url = new URL(`${server.base}/oauth/authorize`);
    url.searchParams.set("client_id", parApp.id);
    url.searchParams.set("request_uri", pushed.body.request_uri);
    const callback = await authorize(page, url.toString(), user);
    const issued = await tokenRequest(server.base, {
      grant_type: "authorization_code",
      code: callback.searchParams.get("code"),
      redirect_uri: "http://localhost/cb",
      code_verifier: pkce.verifier,
    }, { id: parApp.id, secret: parApp.secret });
    assert.equal(issued.status, 200, JSON.stringify(issued.body));
    await page.context().close();
  });

  it("ends the browser session on logout", async function () {
    const page = await newPage();
    const pkce = pkcePair();
    const url = new URL(`${server.base}/oauth/authorize`);
    url.searchParams.set("client_id", web.id);
    url.searchParams.set("redirect_uri", "http://localhost/cb");
    url.searchParams.set("response_type", "code");
    url.searchParams.set("scope", "openid");
    url.searchParams.set("code_challenge", pkce.challenge);
    url.searchParams.set("code_challenge_method", pkce.method);
    await authorize(page, url.toString(), user);
    await page.goto(`${server.base}/oauth/logout`);
    await page.click("button[type=submit]");
    await page.waitForSelector("text=session has ended");
    const next = pkcePair();
    const again = new URL(`${server.base}/oauth/authorize`);
    again.searchParams.set("client_id", web.id);
    again.searchParams.set("redirect_uri", "http://localhost/cb");
    again.searchParams.set("response_type", "code");
    again.searchParams.set("scope", "openid");
    again.searchParams.set("code_challenge", next.challenge);
    again.searchParams.set("code_challenge_method", next.method);
    await page.goto(again.toString());
    await page.waitForSelector("#username");
    await page.context().close();
  });

  it("registers a client dynamically and uses its secret", async function () {
    const registered = await readBody(await fetch(`${server.base}/oauth/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client_name: "Dynamic",
        redirect_uris: ["http://localhost/cb"],
        grant_types: ["client_credentials"],
        scope: "openid",
      }),
    }));
    assert.equal(registered.status, 201, JSON.stringify(registered.body));
    const issued = await tokenRequest(server.base, {
      grant_type: "client_credentials",
      scope: "openid",
    }, { id: registered.body.client_id, secret: registered.body.client_secret });
    assert.equal(issued.status, 200, JSON.stringify(issued.body));
  });
});
