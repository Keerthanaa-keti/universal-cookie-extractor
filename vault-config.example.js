// Cookie Vault — pre-wired defaults so setup is just "sign in".
// Copy this file to `vault-config.js` (gitignored) and fill in your vault's
// PUBLIC values. Both are safe to embed in a client: the anon key is public by
// design and Row Level Security protects the data. The service-role key is NOT
// here — it lives only in the broker Edge Function.
export const VAULT_DEFAULTS = {
  supabase_url: '',        // e.g. https://your-project.supabase.co
  supabase_anon_key: '',   // eyJhbGci...
  owner_email: '',         // optional: pre-fills the sign-in email
};
