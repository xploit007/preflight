import { createClient } from '@supabase/supabase-js';

// Use the service role key so queries never fail because of RLS.
export const supabase = createClient(import.meta.env.VITE_SUPABASE_URL, import.meta.env.VITE_SUPABASE_SERVICE_ROLE_KEY);
