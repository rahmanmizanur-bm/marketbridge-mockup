/**
 * Cloudflare Pages Function - HTTP Basic Auth gate for the whole mockup site.
 *
 * Runs at the edge on EVERY request BEFORE the static index.html is served, so the
 * credentials live only in the Pages environment (env.BASIC_AUTH_USER / BASIC_AUTH_PASS)
 * and are NEVER shipped to the browser or committed to git. This is real gating - unlike
 * a client-side JS password prompt, the secret is server-side and cannot be bypassed by
 * reading the page source.
 *
 * Set the credentials:
 *   - Local dev:  a gitignored `.dev.vars` file (see `.dev.vars.example`), read by
 *                 `wrangler pages dev . --binding ...` / `wrangler pages dev`.
 *   - Production: Cloudflare Pages project -> Settings -> Environment variables (mark as
 *                 Secret), or `wrangler pages secret put BASIC_AUTH_USER` / `..._PASS`.
 *
 * NOTE: This only takes effect when the site is served by Cloudflare Pages. Plain GitHub
 * Pages does NOT run Functions, so the GitHub Pages URL stays ungated - deploy to
 * Cloudflare Pages and use that URL (or put your domain in front of it).
 */
export const onRequest = async (context) => {
  const { request, env, next } = context;

  const user = env.BASIC_AUTH_USER;
  const pass = env.BASIC_AUTH_PASS;

  // Fail closed: if the gate is not configured, deny rather than expose the site.
  if (!user || !pass) {
    return new Response("Auth not configured.", {
      status: 503,
      headers: { "Cache-Control": "no-store" },
    });
  }

  const expected = "Basic " + btoa(`${user}:${pass}`);
  const provided = request.headers.get("Authorization") || "";

  if (provided && timingSafeEqual(provided, expected)) {
    return next();
  }

  return new Response("Authentication required.", {
    status: 401,
    headers: {
      "WWW-Authenticate": 'Basic realm="MarketBridge mockup", charset="UTF-8"',
      "Cache-Control": "no-store",
    },
  });
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
