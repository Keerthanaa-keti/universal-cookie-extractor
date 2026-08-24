// ============================================================================
// Cookie Vault v3 — cookie-broker Edge Function (Deno).
//
// The ONLY read path for remote servers. Servers present a per-server `cvk_`
// token (NOT a Supabase JWT, NOT the service_role key). The broker:
//   1. authenticates the token (SHA-256 hash lookup)
//   2. enforces the server's domain scope
//   3. rate-limits per token
//   4. returns ciphertext + the DEK already sealed to THIS server's public key
//   5. logs every read to access_log (append-only audit)
//
// Zero-knowledge: the broker only moves ciphertext and a DEK that is sealed to
// the requesting server. It holds the service_role key to read the DB but can
// NEVER decrypt cookie values.
//
// Deploy:
//   supabase functions deploy cookie-broker --no-verify-jwt
//   supabase secrets set SUPABASE_URL=... SERVICE_ROLE_KEY=...
// ============================================================================

// SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are auto-injected into every Supabase
// Edge Function — no manual secret needed in production. The bare-name fallbacks are
// for local/e2e runs (Supabase reserves the SUPABASE_ prefix for its own injection).
const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? Deno.env.get("SERVICE_ROLE_KEY")!;
const RATE_LIMIT_PER_MIN = Number(Deno.env.get("RATE_LIMIT_PER_MIN") ?? "120");

const REST = `${SUPABASE_URL}/rest/v1`;
const svcHeaders = {
  apikey: SERVICE_ROLE_KEY,
  Authorization: `Bearer ${SERVICE_ROLE_KEY}`,
  "Content-Type": "application/json",
};

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" },
  });

async function sha256Hex(s: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// scope match: strip leading dots, allow '*', exact, or subdomain suffix
function domainMatches(candidate: string, pattern: string): boolean {
  if (pattern === "*") return true;
  const c = candidate.replace(/^\.+/, "").toLowerCase();
  const p = pattern.replace(/^\.+/, "").toLowerCase();
  return c === p || c.endsWith("." + p);
}

async function rest(path: string): Promise<any[]> {
  const r = await fetch(`${REST}/${path}`, { headers: svcHeaders });
  if (!r.ok) throw new Error(`rest ${path}: ${r.status} ${await r.text()}`);
  return r.json();
}

async function logAccess(row: Record<string, unknown>) {
  try {
    await fetch(`${REST}/access_log`, {
      method: "POST",
      headers: { ...svcHeaders, Prefer: "return=minimal" },
      body: JSON.stringify(row),
    });
  } catch (_e) { /* audit best-effort; never block the response */ }
}

async function touch(table: string, id: string) {
  try {
    await fetch(`${REST}/${table}?id=eq.${id}`, {
      method: "PATCH",
      headers: { ...svcHeaders, Prefer: "return=minimal" },
      body: JSON.stringify({ last_used_at: new Date().toISOString() }),
    });
  } catch (_e) { /* non-fatal */ }
}

interface AuthCtx {
  token_id: string;
  user_id: string;
  server_key_id: string;
  allowed_domains: string[];
  server_label: string;
}

// Returns the auth context, or a Response describing the rejection.
async function authenticate(req: Request): Promise<AuthCtx | Response> {
  const hdr = req.headers.get("authorization") ?? "";
  const m = hdr.match(/^Bearer\s+(cvk_[A-Za-z0-9_-]+)$/);
  if (!m) return json({ error: "missing or malformed token" }, 401);

  const tokenHash = await sha256Hex(m[1]);
  const rows = await rest(
    `access_tokens?token_hash=eq.${tokenHash}` +
      `&select=id,user_id,server_key_id,revoked,expires_at,server_keys(label,allowed_domains,revoked)`,
  );
  const t = rows[0];
  if (!t) return json({ error: "invalid token" }, 401);

  const sk = t.server_keys;
  if (t.revoked || (sk && sk.revoked)) {
    await logAccess({ user_id: t.user_id, server_key_id: t.server_key_id, token_id: t.id, status: "denied_token" });
    return json({ error: "token revoked" }, 403);
  }
  if (t.expires_at && new Date(t.expires_at) < new Date()) {
    await logAccess({ user_id: t.user_id, server_key_id: t.server_key_id, token_id: t.id, status: "denied_token" });
    return json({ error: "token expired" }, 403);
  }

  // rate limit: reads in the last 60s for this token
  const since = new Date(Date.now() - 60_000).toISOString();
  const recent = await rest(
    `access_log?token_id=eq.${t.id}&status=eq.ok&created_at=gte.${since}&select=id`,
  );
  if (recent.length >= RATE_LIMIT_PER_MIN) {
    await logAccess({ user_id: t.user_id, server_key_id: t.server_key_id, token_id: t.id, status: "rate_limited" });
    return json({ error: "rate limit exceeded" }, 429);
  }

  return {
    token_id: t.id,
    user_id: t.user_id,
    server_key_id: t.server_key_id,
    allowed_domains: sk?.allowed_domains ?? [],
    server_label: sk?.label ?? "",
  };
}

function clientMeta(req: Request) {
  return {
    ip: (req.headers.get("x-forwarded-for") ?? "").split(",")[0].trim() || null,
    user_agent: req.headers.get("user-agent") ?? null,
  };
}

async function handleCookies(req: Request, ctx: AuthCtx, domain: string): Promise<Response> {
  const meta = clientMeta(req);
  const base = { user_id: ctx.user_id, server_key_id: ctx.server_key_id, token_id: ctx.token_id, domain, ...meta };

  if (!domain) return json({ error: "domain query param required" }, 400);
  if (!ctx.allowed_domains.some((a) => domainMatches(domain, a))) {
    await logAccess({ ...base, status: "denied_scope" });
    return json({ error: `domain '${domain}' not in this server's scope` }, 403);
  }

  // candidate entries for this owner whose domain is within the request AND within scope
  const candidates = await rest(
    `cookie_entries?user_id=eq.${ctx.user_id}` +
      `&select=id,domain,ciphertext,iv,cookie_count,synced_at,expires_at`,
  );
  const matched = candidates.filter(
    (e) => domainMatches(e.domain, domain) && ctx.allowed_domains.some((a) => domainMatches(e.domain, a)),
  );
  if (matched.length === 0) {
    await logAccess({ ...base, status: "ok", bytes: 0 });
    await touch("access_tokens", ctx.token_id);
    return json({ entries: [], server: ctx.server_label });
  }

  // wrapped DEKs sealed to THIS server for those entries
  const ids = matched.map((e) => e.id).join(",");
  const keys = await rest(
    `entry_keys?recipient_type=eq.server&server_key_id=eq.${ctx.server_key_id}` +
      `&entry_id=in.(${ids})&select=entry_id,wrapped_dek`,
  );
  const wrapById = new Map(keys.map((k) => [k.entry_id, k.wrapped_dek]));

  const entries = matched
    .filter((e) => wrapById.has(e.id))
    .map((e) => ({
      domain: e.domain,
      ciphertext: e.ciphertext,
      iv: e.iv,
      wrapped_dek: wrapById.get(e.id),
      cookie_count: e.cookie_count,
      synced_at: e.synced_at,
      expires_at: e.expires_at,
    }));

  const body = { entries, server: ctx.server_label };
  const bytes = JSON.stringify(body).length;
  await logAccess({ ...base, status: "ok", bytes });
  await touch("access_tokens", ctx.token_id);
  await touch("server_keys", ctx.server_key_id);
  return json(body);
}

async function handleProfile(_req: Request, ctx: AuthCtx): Promise<Response> {
  // The browser profile (UA + client hints + languages + timezone) is vault-wide
  // and not secret. Any valid token for this owner may read it to mimic the browser.
  const rows = await rest(`cookie_vaults?user_id=eq.${ctx.user_id}&select=browser_profile&limit=1`);
  return json({ profile: rows[0]?.browser_profile ?? null, server: ctx.server_label });
}

async function handleDomains(_req: Request, ctx: AuthCtx): Promise<Response> {
  const rows = await rest(
    `cookie_entries?user_id=eq.${ctx.user_id}&select=domain,cookie_count,has_auth_cookies,synced_at`,
  );
  const inScope = rows.filter((e) => ctx.allowed_domains.some((a) => domainMatches(e.domain, a)));
  return json({ domains: inScope, allowed_domains: ctx.allowed_domains, server: ctx.server_label });
}

export async function handler(req: Request): Promise<Response> {
  if (req.method === "OPTIONS") {
    return new Response(null, {
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Headers": "authorization, content-type",
        "Access-Control-Allow-Methods": "GET, OPTIONS",
      },
    });
  }

  const url = new URL(req.url);
  const parts = url.pathname.split("/").filter(Boolean);
  const idx = parts.indexOf("cookie-broker");
  const action = idx >= 0 ? (parts[idx + 1] ?? "") : "";

  if (action === "health") return json({ ok: true, service: "cookie-broker" });

  try {
    const ctx = await authenticate(req);
    if (ctx instanceof Response) return ctx;

    if (action === "cookies") return await handleCookies(req, ctx, url.searchParams.get("domain") ?? "");
    if (action === "domains") return await handleDomains(req, ctx);
    if (action === "profile") return await handleProfile(req, ctx);
    return json({ error: "not found", actions: ["cookies", "domains", "profile", "health"] }, 404);
  } catch (e) {
    return json({ error: "internal error", detail: String(e) }, 500);
  }
}

// Run the server when this module is the entrypoint (Supabase Edge + local).
// BROKER_PORT lets local/e2e runs pick a port; hosted Supabase manages the socket.
if (import.meta.main) {
  const port = Deno.env.get("BROKER_PORT");
  Deno.serve(port ? { port: Number(port) } : {}, handler);
}
