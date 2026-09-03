/**
 * Restore administrator access to a deployment whose sign-in transport has
 * stopped working.
 *
 * Run it on the host, where the deployment's own environment is readable. It
 * needs both secrets: `CORE_SIGNING_SECRET`, which every core route requires,
 * and `QM_BREAK_GLASS_SECRET`, which this route additionally requires and
 * which the deployment was started with. It sets one named principal's
 * password and restores their org_admin grant. It mints no session, and core
 * audits the call.
 *
 *   node --env-file-if-exists=.env scripts/break-glass.ts <principal> <new password>
 *
 * The password may also be supplied on stdin, which keeps it out of the shell
 * history and the process table.
 */
import { createInterface } from "node:readline/promises";
import { signRequest } from "../src/auth/source-auth.ts";

const [principalId, passwordArg] = process.argv.slice(2);
const coreApiUrl = (process.env.CORE_API_URL ?? "http://localhost:8080").replace(/\/$/, "");
const signingSecret = process.env.CORE_SIGNING_SECRET ?? "";
const breakGlassSecret = process.env.QM_BREAK_GLASS_SECRET ?? "";

function die(message: string): never {
  console.error(`break-glass: ${message}`);
  process.exit(1);
}

if (!principalId) die("usage: break-glass.ts <principal> [new password]");
if (!signingSecret) die("CORE_SIGNING_SECRET is not set — core will refuse an unsigned request");
if (!breakGlassSecret) die("QM_BREAK_GLASS_SECRET is not set — this deployment has no break-glass path armed");

const password =
  passwordArg ??
  (await (async (): Promise<string> => {
    const rl = createInterface({ input: process.stdin, output: process.stderr });
    const answer = await rl.question(`New password for ${principalId}: `);
    rl.close();
    return answer;
  })());
if (password.length < 8) die("a password must be at least 8 characters");

const path = "/v1/auth/break-glass";
const body = JSON.stringify({ principalId, password });
const timestamp = Math.floor(Date.now() / 1000);
const res = await fetch(`${coreApiUrl}${path}`, {
  method: "POST",
  headers: {
    "content-type": "application/json",
    authorization: `Bearer ${breakGlassSecret}`,
    "x-timestamp": String(timestamp),
    "x-signature": signRequest(signingSecret, timestamp, `POST\n${path}\n${body}`),
  },
  body,
});
const text = await res.text();
if (!res.ok) die(`core refused the call: HTTP ${res.status} ${text}`);
console.error(
  `break-glass: ${principalId} can sign in again and holds org_admin. They must choose a new password at the next sign-in. The call is in the audit log.`,
);
