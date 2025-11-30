import assert from "node:assert";
import test from "node:test";
import crypto from "crypto";
import BN from "bn.js";
import { SRP6 } from "./srp6";

const sha1 = (...inputs: (string | Buffer)[]) => {
  const hash = crypto.createHash("sha1");
  for (const input of inputs) {
    if (typeof input === "string") {
      hash.update(input, "utf8");
    } else {
      hash.update(input);
    }
  }
  return hash.digest();
};

test("SRP6 registration and challenge/proof roundtrip", () => {
  const username = "SRPTEST";
  const password = "SUPERSECRET";

  const [saltHex, verifierHex] = SRP6.MakeRegistrationData(
    username.toUpperCase(),
    password.toUpperCase()
  );

  const server = new SRP6(username, saltHex, verifierHex);

  const red = BN.red(SRP6._N);
  const a = new BN(crypto.randomBytes(SRP6.EPHEMERAL_KEY_LENGTH));
  const A = SRP6._g
    .toRed(red)
    .redPow(a)
    .fromRed()
    .toArrayLike(Buffer, "be", SRP6.EPHEMERAL_KEY_LENGTH);

  const u = new BN(sha1(A, server.B));

  const innerHash = sha1(`${username.toUpperCase()}:${password.toUpperCase()}`);
  const x = new BN(sha1(Buffer.from(saltHex, "hex"), innerHash));

  const gx = SRP6._g.toRed(red).redPow(x).fromRed();
  const k = new BN(3);
  const base = new BN(server.B).sub(gx.mul(k)).umod(SRP6._N).toRed(red);

  const S_client = base
    .redPow(a.add(u.mul(x)))
    .fromRed()
    .toArrayLike(Buffer, "be", SRP6.EPHEMERAL_KEY_LENGTH);

  const K_client = SRP6.SHA1Interleave(S_client);

  const NHash = sha1(SRP6.N);
  const gHash = sha1(SRP6.g);
  const NgHash = Buffer.alloc(SRP6.DIGEST_LENGTH);
  for (let i = 0; i < SRP6.DIGEST_LENGTH; i++) {
    NgHash[i] = NHash[i] ^ gHash[i];
  }

  const clientM = sha1(
    NgHash,
    sha1(username.toUpperCase()),
    Buffer.from(saltHex, "hex"),
    A,
    server.B,
    K_client
  );

  const sessionKey = server.VerifyChallengeResponse(A, clientM);
  assert.ok(sessionKey, "Server should accept valid SRP proof");
  assert.ok(sessionKey.equals(K_client), "Session keys should match");

  const serverM2 = SRP6.GetSessionVerifier(A, clientM, sessionKey);
  const expectedM2 = sha1(A, clientM, sessionKey);
  assert.ok(
    serverM2.equals(expectedM2),
    "Server proof should match client expectation"
  );
});
