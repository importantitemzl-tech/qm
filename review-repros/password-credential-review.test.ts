// Independent-review repros for 36fc298. Intentionally untracked; not product tests.
import "../test/support/auto-fake-sprites.ts";

import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { createMemoryMap } from "../src/persistence/durable-map.ts";
import { createIdentityService } from "../src/identity/identity-service.ts";
import { createInsecureTestServer, createServer as createCoreServer } from "../src/api/server.ts";
import { buildApp } from "../src/wiring.ts";
import { createMemoryReplayDedupe, type ReplayDedupe } from "../src/auth/replay-dedupe.ts";
import { readBreakGlassConfig } from "../src/auth/break-glass.ts";
import { testConfig } from "../test/support/test-config.ts";

const recoverySecret = "review-only-break-glass-secret-of-sufficient-length";

function durable(): ReplayDedupe {
  const inner = createMemoryReplayDedupe();
  return { durable: true, claim: (id, expiresAtMs) => inner.claim(id, expiresAtMs) };
}

function start(
  opts: {
    breakGlass?: boolean;
    countVerifications?: { calls: number };
    failRecoveryGrant?: boolean;
    secure?: boolean;
  } = {},
) {
  const built = buildApp(testConfig({ dataDir: mkdtempSync(join(tmpdir(), "password-review-")) }));
  const breakGlass = opts.breakGlass
    ? readBreakGlassConfig({
        QM_BREAK_GLASS_PRINCIPAL: "recovery@example.test",
        QM_BREAK_GLASS_SECRET: recoverySecret,
      })
    : undefined;
  const passwordCredentials = opts.countVerifications
    ? {
        ...built.passwordCredentials,
        async verify(identifier: string, password: string) {
          opts.countVerifications!.calls++;
          return built.passwordCredentials.verify(identifier, password);
        },
      }
    : built.passwordCredentials;
  const admin = opts.failRecoveryGrant
    ? {
        ...built.admin,
        async forceGrantOrgAdmin() {
          throw new Error("simulated durable grant-store outage");
        },
      }
    : built.admin;
  const deps = {
    admin,
    sessions: built.sessions,
    auditLog: built.auditLog,
    identity: built.identity,
    directory: built.directory,
    passwordCredentials,
    replayDedupe: durable(),
    ...(breakGlass ? { breakGlass } : {}),
  };
  const server = opts.secure
    ? createCoreServer(built.app, { ...deps, signingSecret: "s".repeat(40) })
    : createInsecureTestServer(built.app, deps);
  server.listen(0);
  return {
    base: `http://localhost:${(server.address() as AddressInfo).port}`,
    built,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

test("REPRO: a replica that refreshed just before a remote deactivation still admits the principal", async () => {
  const backing = createMemoryMap();
  const writer = createIdentityService(backing);
  const staleReplica = createIdentityService(backing);
  await staleReplica.refresh(); // records an empty snapshot and starts the 10s minimum-refresh interval
  await writer.deactivate("account@example.test", "manual");
  await staleReplica.refresh();
  assert.equal(staleReplica.classify("account@example.test").type, "guest");
});

test("REPRO: a rate-limited password attempt bypasses the decoy verification work", async () => {
  const observed = { calls: 0 };
  const s = start({ countVerifications: observed });
  try {
    for (let attempt = 0; attempt < 51; attempt++) {
      const r = await fetch(`${s.base}/v1/auth/broker/password/verify`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          identifier: `probe-${attempt}@example.test`,
          password: "not-a-real-password",
          ip: "198.51.100.4",
        }),
      });
      assert.equal(r.status, 200);
    }
    // The 51st request must execute comparable KDF work if it is to be timing-indistinguishable.
    assert.equal(observed.calls, 51);
  } finally {
    await s.close();
  }
});

test("REPRO: the broker password endpoint is present when password transport was not selected", async () => {
  const s = start();
  try {
    const r = await fetch(`${s.base}/v1/auth/broker/password/verify`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ identifier: "nobody@example.test", password: "not-a-real-password", ip: "198.51.100.2" }),
    });
    assert.equal(r.status, 404);
  } finally {
    await s.close();
  }
});

test("REPRO: an unarmed break-glass endpoint is observable as source-authenticated rather than absent", async () => {
  const s = start({ secure: true });
  try {
    const r = await fetch(`${s.base}/v1/auth/break-glass`, { method: "POST" });
    assert.equal(r.status, 404);
  } finally {
    await s.close();
  }
});

test("REPRO: boot-armed break-glass can be replayed indefinitely", async () => {
  const s = start({ breakGlass: true });
  try {
    const call = (password: string) =>
      fetch(`${s.base}/v1/auth/break-glass`, {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${recoverySecret}` },
        body: JSON.stringify({ principalId: "recovery@example.test", password }),
      });
    assert.equal((await call("first-recovery-password")).status, 200);
    assert.notEqual((await call("second-recovery-password")).status, 200);
  } finally {
    await s.close();
  }
});

test("REPRO: break-glass reports recovery success even when restoring org_admin failed", async () => {
  const s = start({ breakGlass: true, failRecoveryGrant: true });
  try {
    const r = await fetch(`${s.base}/v1/auth/break-glass`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${recoverySecret}` },
      body: JSON.stringify({ principalId: "recovery@example.test", password: "recovered-password" }),
    });
    assert.notEqual(r.status, 200);
  } finally {
    await s.close();
  }
});

test("REPRO: an authenticated break-glass refusal is not audited", async () => {
  const s = start({ breakGlass: true });
  try {
    const r = await fetch(`${s.base}/v1/auth/break-glass`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${recoverySecret}` },
      body: JSON.stringify({ principalId: "recovery@example.test", password: "short" }),
    });
    assert.equal(r.status, 400);
    assert.ok((await s.built.auditLog.events()).some((event) => event.action === "break-glass.refused"));
  } finally {
    await s.close();
  }
});
