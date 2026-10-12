import { createClient } from '@supabase/supabase-js';

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY);

// Verifies the Supabase access token on every request. The user never comes from the body.
export async function requireUser(req, res, next) {
  const token = (req.headers.authorization || '').replace(/^Bearer /, '');
  const { data, error } = await supabase.auth.getUser(token);
  if (error || !data.user) return res.status(401).json({ error: 'Sign in required' });
  req.user = data.user;
  req.accessToken = token;
  next();
}

export function requireAdmin(req, res, next) {
  if (req.user.app_metadata?.role !== 'admin') return res.status(403).json({ error: 'Admins only' });
  next();
}

/** Supabase client that runs queries as the signed-in user, so RLS applies. */
export function userClient(req) {
  return createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY, {
    global: { headers: { Authorization: `Bearer ${req.accessToken}` } },
  });
}
