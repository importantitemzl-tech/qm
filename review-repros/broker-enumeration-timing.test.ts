// Independent-review repro for 36fc298. Intentionally untracked; not a product test.
import assert from "node:assert/strict";
import test from "node:test";
import { authorizeQuery, fakePasswords, hiddenRequestToken, startHarness } from "../plugins/auth/test/helpers.ts";

const form = (entries: Record<string, string>) => ({
  method: "POST",
  headers: { "content-type": "application/x-www-form-urlencoded" },
  body: new URLSearchParams(entries).toString(),
});

async function requestToken(base: string): Promise<string> {
  const page = await fetch(`${base}/authorize?${authorizeQuery()}`);
  return hiddenRequestToken(await page.text());
}

test("REPRO: malformed and syntactically valid refused sign-ins have distinguishable timings", async () => {
  const passwords = fakePasswords({ "member@example.test": { password: "correct-password" } });
  const realVerify = passwords.verify.bind(passwords);
  passwords.verify = async (args) => {
    await new Promise<void>((resolve) => setTimeout(resolve, 250));
    return realVerify(args);
  };
  const h = await startHarness({
    env: { AUTH_CREDENTIAL_TRANSPORT: "password", CORE_SIGNING_SECRET: "x".repeat(40) },
    passwords,
  });
  try {
    assert.equal(h.cfg.credentialTransport, "password");
    const malformedToken = await requestToken(h.base);
    const malformedStarted = performance.now();
    const malformed = await fetch(
      `${h.base}/authorize`,
      form({ request: malformedToken, email: "not-an-email", password: "wrong-password" }),
    );
    assert.equal(malformed.status, 400);
    const malformedMs = performance.now() - malformedStarted;

    const validToken = await requestToken(h.base);
    const validStarted = performance.now();
    const valid = await fetch(
      `${h.base}/authorize`,
      form({ request: validToken, email: "admin@example.com", password: "wrong-password" }),
    );
    assert.equal(valid.status, 400);
    const validMs = performance.now() - validStarted;

    assert.equal(passwords.calls.length, 1);
    assert.ok(Math.abs(validMs - malformedMs) < 100, `malformed=${malformedMs}ms valid=${validMs}ms`);
  } finally {
    await h.close();
  }
});
