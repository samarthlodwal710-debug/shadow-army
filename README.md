# 🌑 Shadow Army — Supabase Ready

Username + password authentication with NO email/phone.

## Supabase
1. Open SQL Editor.
2. Run `supabase.sql` once.
3. The script creates `auth_accounts` for password hashes and removes the old dependency on `auth.users` from `profiles`.

## Netlify environment variables
Set these in Netlify → Site configuration → Environment variables:
- `SUPABASE_URL`
- `SUPABASE_SERVICE_ROLE_KEY`
- `SESSION_SECRET` (long random secret)

Never put the service-role key in frontend JavaScript.

## Deploy
Upload/publish the project to Netlify. The `netlify.toml` file routes the server function.
