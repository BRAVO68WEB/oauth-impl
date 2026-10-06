const { chromium } = require("playwright");
const { TOTP, Secret } = require("otpauth");

let browser;

function isCallback(current) {
  let parsed;
  try {
    parsed = new URL(current);
  } catch {
    return false;
  }
  if (parsed.pathname === "/e2e-callback") {
    return true;
  }
  return parsed.hostname === "localhost" && (parsed.pathname === "/cb" || parsed.pathname === "/cb/");
}

function isStep(current) {
  if (isCallback(current)) {
    return true;
  }
  let parsed;
  try {
    parsed = new URL(current);
  } catch {
    return false;
  }
  return parsed.pathname === "/consent" || parsed.pathname === "/mfa/enroll";
}

async function ensureBrowser() {
  if (!browser) {
    const headed = process.env.HEADED === "1" || process.env.HEADLESS === "false";
    browser = await chromium.launch({ headless: !headed });
  }
  return browser;
}

async function closeBrowser() {
  if (browser) {
    await browser.close();
    browser = null;
  }
}

async function newPage() {
  const instance = await ensureBrowser();
  const context = await instance.newContext();
  const page = await context.newPage();
  let origin = "";
  page.on("request", (request) => {
    try {
      const parsed = new URL(request.url());
      if (parsed.hostname === "127.0.0.1") {
        origin = parsed.origin;
      }
    } catch {
      // Ignore malformed URLs from the browser.
    }
  });
  page.on("response", (response) => {
    if (!response.headers()["set-cookie"]) {
      return;
    }
    page.context().cookies().then((cookies) => {
      if (cookies.some((cookie) => cookie.name === "session_id")) {
        page._oauthCookies = cookies;
      }
    }).catch(() => {});
  });
  // The OAuth host is 127.0.0.1 and the allowed callback is http://localhost.
  // Land back on the OAuth host so the session cookie stays on a same-site document.
  await page.route(/\/e2e-callback(?:\?|#|$)/, async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "text/html",
      body: "<h1>callback</h1>",
    });
  });
  await page.route(/http:\/\/localhost\/cb/, async (route) => {
    const incoming = new URL(route.request().url());
    if (!origin) {
      await route.fulfill({
        status: 200,
        contentType: "text/html",
        body: "<h1>callback</h1>",
      });
      return;
    }
    const back = new URL("/e2e-callback", origin);
    back.search = incoming.search;
    await route.fulfill({
      status: 302,
      headers: { location: back.toString() },
      body: "",
    });
  });
  return page;
}

async function submitLogin(page, username, password) {
  await page.fill("#username", username);
  await page.fill("#password", password);
  await page.click("button[type=submit]");
}

async function submitEnrollment(page) {
  await page.waitForURL((current) => {
    try {
      return new URL(current).pathname === "/mfa/enroll";
    } catch {
      return false;
    }
  }, { timeout: 15000 });
  const secret = (await page.locator(".secret-box").textContent()).trim();
  const code = new TOTP({
    secret: Secret.fromBase32(secret),
    digits: 6,
    period: 30,
    algorithm: "SHA1",
  }).generate();
  await page.fill("#code", code);
  await page.click("button[type=submit]");
}

async function failDump(page, err) {
  const text = await page.locator("body").innerText().catch(() => "");
  throw new Error(`${err.message}\nURL ${page.url()}\n${text.slice(0, 800)}`);
}

async function waitForStep(page) {
  try {
    await page.waitForURL(isStep, { timeout: 20000 });
  } catch (err) {
    await failDump(page, err);
  }
}

async function waitForCallback(page) {
  if (isCallback(page.url())) {
    return new URL(page.url());
  }
  try {
    await page.waitForURL(isCallback, { timeout: 20000 });
  } catch (err) {
    await failDump(page, err);
  }
  return new URL(page.url());
}

async function restoreSessionCookies(page) {
  if (!Array.isArray(page._oauthCookies) || page._oauthCookies.length === 0) {
    return;
  }
  await page.context().addCookies(page._oauthCookies);
}

async function authorize(page, url, options) {
  await page.goto(url);
  if (page.url().includes("/login")) {
    await submitLogin(page, options.username, options.password);
    await waitForStep(page);
  }
  if (page.url().includes("/mfa/enroll") || options.enroll) {
    await submitEnrollment(page);
    await waitForStep(page);
  }
  if (options.consent !== false && page.url().includes("/consent")) {
    page._oauthCookies = await page.context().cookies();
    const decision = options.consent || "approve";
    try {
      await Promise.all([
        page.waitForURL(isCallback, { timeout: 20000 }),
        page.locator(`button[value="${decision}"]`).click(),
      ]);
    } catch (err) {
      await failDump(page, err);
    }
  }
  const callback = await waitForCallback(page);
  await restoreSessionCookies(page);
  return callback;
}

module.exports = {
  ensureBrowser,
  closeBrowser,
  newPage,
  submitLogin,
  authorize,
  waitForCallback,
};
