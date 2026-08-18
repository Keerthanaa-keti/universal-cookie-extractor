-- ============================================================================
-- Cookie Vault v3 — Zero-Knowledge Scoped Broker schema
-- Apply to a FRESH Supabase project (Free plan is sufficient).
--   supabase db push   (or paste into the SQL editor)
--
-- Trust model: envelope encryption. Supabase stores only ciphertext + DEKs that
-- are themselves sealed to a recipient public key. The database operator, the
-- broker, and a DB thief cannot read cookie plaintext. Only a holder of a
-- recipient private key (a specific server) or the owner passphrase can decrypt.
--
-- Roles:
--   authenticated  -> the OWNER (extension / admin CLI), constrained by RLS to own rows
--   service_role   -> the BROKER Edge Function only (bypasses RLS); never given to servers
--   servers        -> NO database credentials at all; they talk only to the broker
-- ============================================================================

-- gen_random_uuid() is built in on Supabase (pgcrypto). No uuid-ossp needed.

-- ---------------------------------------------------------------------------
-- 1. Vaults — one per user; holds the owner-wrap KDF salt
-- ---------------------------------------------------------------------------
create table if not exists public.cookie_vaults (
  id          uuid primary key default gen_random_uuid(),
  user_id     uuid not null references auth.users(id) on delete cascade,
  vault_name  text not null default 'default',
  owner_salt  text not null,                       -- base64; PBKDF2 salt for owner-wrap KEK
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now(),
  unique (user_id, vault_name)
);
create index if not exists idx_cookie_vaults_user on public.cookie_vaults(user_id);

-- ---------------------------------------------------------------------------
-- 2. Registered servers — one X25519 public key + domain scope per server
-- ---------------------------------------------------------------------------
create table if not exists public.server_keys (
  id              uuid primary key default gen_random_uuid(),
  user_id         uuid not null references auth.users(id) on delete cascade,
  label           text not null,
  public_key      text not null,                   -- base64url raw X25519 public key (32 bytes)
  allowed_domains text[] not null default '{}',    -- scope; '*' element = all domains
  revoked         boolean not null default false,
  created_at      timestamptz not null default now(),
  revoked_at      timestamptz,
  last_used_at    timestamptz,
  unique (user_id, label)
);
create index if not exists idx_server_keys_user on public.server_keys(user_id);
create index if not exists idx_server_keys_user_active on public.server_keys(user_id) where not revoked;

-- ---------------------------------------------------------------------------
-- 3. Cookie entries — one encrypted blob per domain per vault
--    (domain is plaintext for scoping/queries; cookie values are encrypted)
-- ---------------------------------------------------------------------------
create table if not exists public.cookie_entries (
  id               uuid primary key default gen_random_uuid(),
  vault_id         uuid not null references public.cookie_vaults(id) on delete cascade,
  user_id          uuid not null references auth.users(id) on delete cascade,
  domain           text not null,
  ciphertext       text not null,                  -- AES-256-GCM(cookiesJSON, DEK), base64
  iv               text not null,                  -- GCM IV, base64
  cookie_count     integer not null default 0,
  has_auth_cookies boolean not null default false,
  expires_at       timestamptz,                    -- earliest cookie expiry in this batch
  synced_at        timestamptz not null default now(),
  unique (vault_id, domain)
);
create index if not exists idx_cookie_entries_vault   on public.cookie_entries(vault_id);
create index if not exists idx_cookie_entries_user    on public.cookie_entries(user_id);
create index if not exists idx_cookie_entries_domain  on public.cookie_entries(domain);
create index if not exists idx_cookie_entries_expires on public.cookie_entries(expires_at);

-- ---------------------------------------------------------------------------
-- 4. Entry keys — the wrapped DEK for each recipient (owner + each server)
--    wrapped_dek: {epk,iv,ct} (server, ECIES) | {salt,iv,ct} (owner, PBKDF2+AES-GCM)
-- ---------------------------------------------------------------------------
create table if not exists public.entry_keys (
  id             uuid primary key default gen_random_uuid(),
  entry_id       uuid not null references public.cookie_entries(id) on delete cascade,
  user_id        uuid not null references auth.users(id) on delete cascade,
  recipient_type text not null check (recipient_type in ('owner','server')),
  server_key_id  uuid references public.server_keys(id) on delete cascade,
  wrapped_dek    jsonb not null,
  created_at     timestamptz not null default now(),
  constraint entry_keys_recipient_chk check (
    (recipient_type = 'owner'  and server_key_id is null) or
    (recipient_type = 'server' and server_key_id is not null)
  )
);
create unique index if not exists entry_keys_owner_uq  on public.entry_keys(entry_id)               where recipient_type = 'owner';
create unique index if not exists entry_keys_server_uq on public.entry_keys(entry_id, server_key_id) where recipient_type = 'server';
create index if not exists idx_entry_keys_entry  on public.entry_keys(entry_id);
create index if not exists idx_entry_keys_server on public.entry_keys(server_key_id);
create index if not exists idx_entry_keys_user   on public.entry_keys(user_id);

-- ---------------------------------------------------------------------------
-- 5. Access tokens — per-server broker credentials (only the hash is stored)
-- ---------------------------------------------------------------------------
create table if not exists public.access_tokens (
  id            uuid primary key default gen_random_uuid(),
  user_id       uuid not null references auth.users(id) on delete cascade,
  server_key_id uuid not null references public.server_keys(id) on delete cascade,
  token_hash    text not null unique,              -- sha256 hex of raw cvk_ token
  token_prefix  text not null,                     -- e.g. 'cvk_ab12cd' for display only
  label         text,
  expires_at    timestamptz,
  revoked       boolean not null default false,
  created_at    timestamptz not null default now(),
  last_used_at  timestamptz
);
create index if not exists idx_access_tokens_user   on public.access_tokens(user_id);
create index if not exists idx_access_tokens_server on public.access_tokens(server_key_id);

-- ---------------------------------------------------------------------------
-- 6. Access log — read audit; written by the broker (service_role), read by owner
-- ---------------------------------------------------------------------------
create table if not exists public.access_log (
  id            uuid primary key default gen_random_uuid(),
  user_id       uuid not null references auth.users(id) on delete cascade,
  server_key_id uuid references public.server_keys(id) on delete set null,
  token_id      uuid references public.access_tokens(id) on delete set null,
  domain        text,
  ip            text,
  user_agent    text,
  bytes         integer,
  status        text not null default 'ok',        -- ok|denied_scope|denied_token|rate_limited|error
  created_at    timestamptz not null default now()
);
create index if not exists idx_access_log_user       on public.access_log(user_id, created_at desc);
create index if not exists idx_access_log_server     on public.access_log(server_key_id);
create index if not exists idx_access_log_token_time on public.access_log(token_id, created_at desc); -- rate limiting

-- ---------------------------------------------------------------------------
-- 7. Sync log — owner write audit (from the extension)
-- ---------------------------------------------------------------------------
create table if not exists public.sync_log (
  id           uuid primary key default gen_random_uuid(),
  user_id      uuid not null references auth.users(id) on delete cascade,
  vault_id     uuid references public.cookie_vaults(id) on delete cascade,
  action       text not null,                      -- sync|rewrap|delete
  domain_count integer not null default 0,
  cookie_count integer not null default 0,
  server_count integer not null default 0,
  client_type  text not null default 'extension',
  created_at   timestamptz not null default now()
);
create index if not exists idx_sync_log_user on public.sync_log(user_id);

-- ---------------------------------------------------------------------------
-- 8. Row Level Security — owner-only; broker uses service_role (bypasses RLS)
--    auth.uid() wrapped in (select ...) so it is evaluated once, not per row.
-- ---------------------------------------------------------------------------
alter table public.cookie_vaults  enable row level security;
alter table public.server_keys    enable row level security;
alter table public.cookie_entries enable row level security;
alter table public.entry_keys     enable row level security;
alter table public.access_tokens  enable row level security;
alter table public.access_log     enable row level security;
alter table public.sync_log       enable row level security;

-- Owner full control of own rows on config/data tables
do $$
declare t text;
begin
  foreach t in array array[
    'cookie_vaults','server_keys','cookie_entries','entry_keys','access_tokens','sync_log'
  ] loop
    execute format($f$
      drop policy if exists %1$s_owner_all on public.%1$s;
      create policy %1$s_owner_all on public.%1$s
        for all to authenticated
        using ((select auth.uid()) = user_id)
        with check ((select auth.uid()) = user_id);
    $f$, t);
  end loop;
end $$;

-- access_log is append-only from the broker; owner may only READ it (tamper-resistant audit)
drop policy if exists access_log_owner_read on public.access_log;
create policy access_log_owner_read on public.access_log
  for select to authenticated
  using ((select auth.uid()) = user_id);

-- ---------------------------------------------------------------------------
-- 9. Maintenance — updated_at trigger + expired-cookie cleanup
-- ---------------------------------------------------------------------------
create or replace function public.update_updated_at()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

drop trigger if exists cookie_vaults_updated_at on public.cookie_vaults;
create trigger cookie_vaults_updated_at
  before update on public.cookie_vaults
  for each row execute function public.update_updated_at();

-- Delete expired cookie entries. security definer so it can run from a scheduled job.
create or replace function public.cleanup_expired_cookies()
returns integer
language plpgsql
security definer
set search_path = ''
as $$
declare deleted_count integer;
begin
  delete from public.cookie_entries
   where expires_at is not null and expires_at < now();
  get diagnostics deleted_count = row_count;
  return deleted_count;
end;
$$;
revoke execute on function public.cleanup_expired_cookies() from public, anon, authenticated;

-- ============================================================================
-- Done. Next: deploy the cookie-broker Edge Function and set its secrets
-- (SERVICE_ROLE_KEY, SUPABASE_URL). Servers never receive either.
-- ============================================================================
