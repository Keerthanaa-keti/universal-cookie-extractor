-- Cookie Vault Schema
-- Tables for encrypted cloud cookie storage with RLS

-- Enable UUID generation
create extension if not exists "uuid-ossp";

-- Vault: one per user (supports multiple vaults in future)
create table if not exists cookie_vaults (
  id uuid primary key default uuid_generate_v4(),
  user_id uuid not null references auth.users(id) on delete cascade,
  vault_name text not null default 'default',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique(user_id, vault_name)
);

-- Cookie entries: one row per domain per vault
-- Domain stored in plaintext for queries; all cookie data encrypted
create table if not exists cookie_entries (
  id uuid primary key default uuid_generate_v4(),
  vault_id uuid not null references cookie_vaults(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  domain text not null,
  encrypted_data text not null,       -- AES-256-GCM ciphertext (base64)
  iv text not null,                   -- initialization vector (base64)
  salt text not null,                 -- PBKDF2 salt (base64)
  cookie_count integer not null default 0,
  has_auth_cookies boolean not null default false,
  expires_at timestamptz,             -- earliest cookie expiry in this batch
  synced_at timestamptz not null default now(),
  unique(vault_id, domain)
);

-- Sync log: audit trail
create table if not exists sync_log (
  id uuid primary key default uuid_generate_v4(),
  user_id uuid not null references auth.users(id) on delete cascade,
  vault_id uuid not null references cookie_vaults(id) on delete cascade,
  action text not null,               -- 'sync', 'delete', 'full_sync'
  domain_count integer not null default 0,
  cookie_count integer not null default 0,
  client_type text not null default 'extension', -- 'extension', 'python', 'node'
  created_at timestamptz not null default now()
);

-- Indexes
create index if not exists idx_cookie_entries_domain on cookie_entries(domain);
create index if not exists idx_cookie_entries_vault_domain on cookie_entries(vault_id, domain);
create index if not exists idx_cookie_entries_expires on cookie_entries(expires_at);
create index if not exists idx_cookie_entries_user on cookie_entries(user_id);
create index if not exists idx_sync_log_user on sync_log(user_id);
create index if not exists idx_cookie_vaults_user on cookie_vaults(user_id);

-- Row Level Security
alter table cookie_vaults enable row level security;
alter table cookie_entries enable row level security;
alter table sync_log enable row level security;

-- RLS Policies: users can only access their own data
create policy "Users can read own vaults"
  on cookie_vaults for select
  using (auth.uid() = user_id);

create policy "Users can insert own vaults"
  on cookie_vaults for insert
  with check (auth.uid() = user_id);

create policy "Users can update own vaults"
  on cookie_vaults for update
  using (auth.uid() = user_id);

create policy "Users can delete own vaults"
  on cookie_vaults for delete
  using (auth.uid() = user_id);

create policy "Users can read own cookie entries"
  on cookie_entries for select
  using (auth.uid() = user_id);

create policy "Users can insert own cookie entries"
  on cookie_entries for insert
  with check (auth.uid() = user_id);

create policy "Users can update own cookie entries"
  on cookie_entries for update
  using (auth.uid() = user_id);

create policy "Users can delete own cookie entries"
  on cookie_entries for delete
  using (auth.uid() = user_id);

create policy "Users can read own sync logs"
  on sync_log for select
  using (auth.uid() = user_id);

create policy "Users can insert own sync logs"
  on sync_log for insert
  with check (auth.uid() = user_id);

-- Updated_at trigger for cookie_vaults
create or replace function update_updated_at()
returns trigger as $$
begin
  new.updated_at = now();
  return new;
end;
$$ language plpgsql;

create trigger cookie_vaults_updated_at
  before update on cookie_vaults
  for each row execute function update_updated_at();

-- Cleanup function: delete expired cookie entries
create or replace function cleanup_expired_cookies()
returns integer as $$
declare
  deleted_count integer;
begin
  delete from cookie_entries
  where expires_at is not null and expires_at < now();
  get diagnostics deleted_count = row_count;
  return deleted_count;
end;
$$ language plpgsql security definer;
