import { createClient } from '@supabase/supabase-js';

// The anon key is public by design. RLS policies decide what it can read.
export const supabase = createClient(import.meta.env.VITE_SUPABASE_URL, import.meta.env.VITE_SUPABASE_ANON_KEY);
