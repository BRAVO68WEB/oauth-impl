const assert = require("node:assert/strict");
const { generateKeyPair, exportJWK, compactDecrypt } = require("jose");
const { startServer } = require("../support/server");
const { shortID } = require("../support/pkce");
const { createUser, createClient, tokenRequest, userInfo } = require("../support/oauth");

describe("encrypted ID token", function () {
  let server;
  let user;
  let privateKey;

  before(async function () {
    this.timeout(60000);
    server = await startServer();
    user = await createUser(server, { username: shortID("jwe") });
    const keys = await generateKeyPair("RSA-OAEP-256");
    privateKey = keys.privateKey;
    const jwk = await exportJWK(keys.publicKey);
    jwk.kid = "enc-1";
    jwk.use = "enc";
    jwk.alg = "RSA-OAEP-256";
    const client = await createClient(server, {
      name: "Encrypted",
      redirect_uris: ["http://localhost/cb"],
      grant_types: ["password"],
      scopes: ["openid", "profile"],
      jwks: JSON.stringify({ keys: [jwk] }),
      id_token_encrypted_response_alg: "RSA-OAEP-256",
      id_token_encrypted_response_enc: "A256GCM",
      userinfo_encrypted_response_alg: "RSA-OAEP-256",
      userinfo_encrypted_response_enc: "A256GCM",
    });
    const issued = await tokenRequest(server.base, {
      grant_type: "password",
      username: user.username,
      password: user.password,
      scope: "openid profile",
    }, client);
    assert.equal(issued.status, 200, JSON.stringify(issued.body));
    assert.equal(issued.body.id_token.split(".").length, 5);
    const decrypted = await compactDecrypt(issued.body.id_token, privateKey);
    const inner = decrypted.plaintext.toString();
    const payload = JSON.parse(Buffer.from(inner.split(".")[1], "base64url").toString());
    assert.equal(payload.sub, user.id);

    const info = await userInfo(server.base, issued.body.access_token);
    assert.equal(info.status, 200, info.text.slice(0, 200));
    assert.equal(info.text.split(".").length, 5);
    const userInfoJWT = await compactDecrypt(info.text, privateKey);
    const userInfoInner = userInfoJWT.plaintext.toString();
    const userInfoPayload = JSON.parse(Buffer.from(userInfoInner.split(".")[1], "base64url").toString());
    assert.equal(userInfoPayload.sub, user.id);
  });

  after(async function () {
    if (server) {
      await server.stop();
    }
  });

  it("decrypts the nested ID token and UserInfo", function () {
    assert.ok(privateKey);
  });
});
