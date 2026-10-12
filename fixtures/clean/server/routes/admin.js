import { Router } from 'express';
import { createClient } from '@supabase/supabase-js';

const router = Router();
// Listing users needs the service role key; this router is mounted behind requireAdmin.
const supabaseAdmin = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);

router.get('/users', async (req, res) => {
  const { data, error } = await supabaseAdmin.auth.admin.listUsers({ page: 1, perPage: 50 });
  if (error) return res.status(500).json({ error: 'Could not list users' });
  res.json(data.users.map((u) => ({ id: u.id, email: u.email })));
});

export default router;
