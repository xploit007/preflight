const { createClient } = require('@supabase/supabase-js');

// Server-side client with full access (bypasses RLS).
const supabaseAdmin = createClient(process.env.VITE_SUPABASE_URL, process.env.VITE_SUPABASE_SERVICE_ROLE_KEY);

module.exports = { supabaseAdmin };
