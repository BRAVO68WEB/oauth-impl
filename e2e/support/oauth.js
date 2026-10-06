const assert = require("node:assert/strict");

const MGMT_ID = "e2e-mgmt";
const MGMT_SECRET = "e2e-mgmt-secret";

async function readBody(response) {
  const text = await response.text();
  let body = text;
  try {
    body = text ? JSON.parse(text) : {};
  } catch {
    body = { raw: text };
  }
  return { status: response.status, body, text };
}

function basic(id, secret) {
  return `Basic ${Buffer.from(`${id}:${secret}`).toString("base64")}`;
}

async function managementToken(server) {
  if (server.managementToken) {
    return server.managementToken;
  }
  const { status, body } = await tokenRequest(server.base, {
    grant_type: "client_credentials",
    scope: "management",
  }, { id: MGMT_ID, secret: MGMT_SECRET });
  assert.equal(status, 200, JSON.stringify(body));
  server.managementToken = body.access_token;
  return server.managementToken;
}

async function api(server, method, pathname, payload) {
  const token = await managementToken(server);
  const response = await fetch(server.base + pathname, {
    method,
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: payload === undefined ? undefined : JSON.stringify(payload),
  });
  return readBody(response);
}

async function createUser(server, fields) {
  const username = fields.username;
  const password = fields.password || "correct-horse";
  const { status, body } = await api(server, "POST", "/api/users", {
    username,
    password,
    email: fields.email || `${username}@example.com`,
    email_verified: true,
  });
  assert.equal(status, 201, JSON.stringify(body));
  return { ...body, username, password };
}

async function createClient(server, fields) {
  const { status, body } = await api(server, "POST", "/api/clients", fields);
  assert.equal(status, 201, JSON.stringify(body));
  return body;
}

async function tokenRequest(base, params, client, extraHeaders) {
  const body = new URLSearchParams(params);
  const headers = { "Content-Type": "application/x-www-form-urlencoded", ...(extraHeaders || {}) };
  if (client && client.secret) {
    headers.Authorization = basic(client.id, client.secret);
  } else if (client && client.id) {
    body.set("client_id", client.id);
  }
  const response = await fetch(`${base}/oauth/token`, { method: "POST", headers, body });
  return readBody(response);
}

async function introspect(base, client, token) {
  const response = await fetch(`${base}/oauth/introspect`, {
    method: "POST",
    headers: {
      Authorization: basic(client.id, client.secret),
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({ token }),
  });
  return readBody(response);
}

async function revoke(base, client, token) {
  const response = await fetch(`${base}/oauth/revoke`, {
    method: "POST",
    headers: {
      Authorization: basic(client.id, client.secret),
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({ token, token_type_hint: "access_token" }),
  });
  return readBody(response);
}

async function userInfo(base, accessToken, scheme) {
  const response = await fetch(`${base}/oidc/userinfo`, {
    headers: { Authorization: `${scheme || "Bearer"} ${accessToken}` },
  });
  return readBody(response);
}

function decodeJwt(token) {
  return JSON.parse(Buffer.from(token.split(".")[1], "base64url").toString());
}

function jwtHeader(token) {
  return JSON.parse(Buffer.from(token.split(".")[0], "base64url").toString());
}

module.exports = {
  MGMT_ID,
  MGMT_SECRET,
  readBody,
  managementToken,
  api,
  createUser,
  createClient,
  tokenRequest,
  introspect,
  revoke,
  userInfo,
  decodeJwt,
  jwtHeader,
};
