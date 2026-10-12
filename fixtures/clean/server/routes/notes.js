import { Router } from 'express';
import { z } from 'zod';
import { userClient } from '../auth.js';

const router = Router();
const NoteInput = z.object({ title: z.string().min(1).max(200), body: z.string().max(10_000) }).strict();

router.get('/', async (req, res) => {
  const { data, error } = await userClient(req).from('notes').select('id, title, body').eq('user_id', req.user.id);
  if (error) return res.status(500).json({ error: 'Could not load notes' });
  res.json(data);
});

router.get('/:id', async (req, res) => {
  const { data } = await userClient(req).from('notes').select('id, title, body').eq('id', req.params.id).eq('user_id', req.user.id).maybeSingle();
  if (!data) return res.status(404).json({ error: 'Not found' });
  res.json(data);
});

router.post('/', async (req, res) => {
  const input = NoteInput.parse(req.body);
  const { data, error } = await userClient(req).from('notes').insert({ ...input, user_id: req.user.id }).select().single();
  if (error) return res.status(400).json({ error: 'Could not save note' });
  res.status(201).json(data);
});

export default router;
