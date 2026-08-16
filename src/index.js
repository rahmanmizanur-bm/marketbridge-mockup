/**
 * Cloudflare Worker - serves the MarketBridge mockup behind HTTP Basic Auth.
 *
 * The Worker runs FIRST on every request (assets.run_worker_first), checks Basic Auth
 * against the Worker env vars (BASIC_AUTH_USER / BASIC_AUTH_PASS), and only then serves the
 * static index.html via the ASSETS binding. The password lives in the Worker environment
 * (dashboard secret, or `.dev.vars` for local `wrangler dev`) and is NEVER shipped to the
 * browser - real gating, not a client-side prompt.
 *
 * Set the credentials:
 *   - Local dev:  a gitignored `.dev.vars` file (see `.dev.vars.example`), read by `wrangler dev`.
 *   - Production: Worker -> Settings -> Variables and Secrets (BASIC_AUTH_USER / BASIC_AUTH_PASS),
 *                 or `npx wrangler secret put BASIC_AUTH_USER` / `... BASIC_AUTH_PASS`.
 */
export default {
  async fetch(request, env) {
    const user = env.BASIC_AUTH_USER;
    const pass = env.BASIC_AUTH_PASS;

    // Fail closed: never expose the site if the gate is not configured.
    if (!user || !pass) {
      return new Response("Auth not configured.", {
        status: 503,
        headers: { "Cache-Control": "no-store" },
      });
    }

    const expected = "Basic " + btoa(`${user}:${pass}`);
    const provided = request.headers.get("Authorization") || "";

    if (!(provided && timingSafeEqual(provided, expected))) {
      return new Response("Authentication required.", {
        status: 401,
        headers: {
          "WWW-Authenticate": 'Basic realm="MarketBridge mockup", charset="UTF-8"',
          "Cache-Control": "no-store",
        },
      });
    }

    // Authenticated -> serve the static asset (index.html).
    return env.ASSETS.fetch(request);
  },
};

/** Constant-time compare so a wrong password cannot be probed via response timing. */
function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}
