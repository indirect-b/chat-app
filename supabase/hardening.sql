-- Chat-app database hardening — apply ONCE as the postgres superuser.
--
-- HOW TO APPLY (Supabase SQL editor, signed in as the project owner,
-- or psql as postgres), AFTER the tables exist (after migration):
--   1. Generate a strong password for the chatapp role. NEVER put a real
--      password in this file — replace the placeholder below at apply time,
--      e.g. with:  openssl rand -base64 24
--   2. Replace '__CHATAPP_ROLE_PASSWORD__' with that generated password.
--   3. Run this whole file. Never commit the file with a real password.
--   4. Update the app's DATABASE_URL to use the chatapp role (same host
--      and database, user chatapp with the generated password) and redeploy.
--   5. Verify: the app works as chatapp; an anon PostgREST key cannot
--      read any table; a connection with a bad certificate fails.
--
-- SCOPE: only the 7 app tables in the public schema. Nothing here touches
-- Supabase's own schemas and nothing global is taken away: with RLS enabled
-- and no policy for anon/authenticated, those roles are denied by default,
-- so no blanket privilege removal is needed.

-- 1. Least-privilege app role. Guarded so re-running the file is safe;
--    a password change is a separate manual step (ALTER ROLE chatapp
--    WITH PASSWORD ... using a freshly generated password).
DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'chatapp') THEN
    CREATE ROLE chatapp WITH LOGIN PASSWORD '__CHATAPP_ROLE_PASSWORD__';
  END IF;
END $$;

-- 2. Row Level Security on all app tables (idempotent).
ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.contacts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.groups ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.media_blobs ENABLE ROW LEVEL SECURITY;

-- 3. Only the app role may use the tables (idempotent via DO block).
DO $$ BEGIN
  CREATE POLICY app_all ON public.users FOR ALL TO chatapp USING (true) WITH CHECK (true);
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;
DO $$ BEGIN
  CREATE POLICY app_all ON public.contacts FOR ALL TO chatapp USING (true) WITH CHECK (true);
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;
DO $$ BEGIN
  CREATE POLICY app_all ON public.messages FOR ALL TO chatapp USING (true) WITH CHECK (true);
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;
DO $$ BEGIN
  CREATE POLICY app_all ON public.groups FOR ALL TO chatapp USING (true) WITH CHECK (true);
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;
DO $$ BEGIN
  CREATE POLICY app_all ON public.reports FOR ALL TO chatapp USING (true) WITH CHECK (true);
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;
DO $$ BEGIN
  CREATE POLICY app_all ON public.settings FOR ALL TO chatapp USING (true) WITH CHECK (true);
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;
DO $$ BEGIN
  CREATE POLICY app_all ON public.media_blobs FOR ALL TO chatapp USING (true) WITH CHECK (true);
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

-- 4. Least-privilege grants: data access only, no DDL, no other schemas.
GRANT SELECT, INSERT, UPDATE, DELETE ON public.users TO chatapp;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.contacts TO chatapp;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.messages TO chatapp;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.groups TO chatapp;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.reports TO chatapp;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.settings TO chatapp;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.media_blobs TO chatapp;
