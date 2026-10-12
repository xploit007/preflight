const express = require('express');
const db = require('../db');
const { supabaseAdmin } = require('../supabase');

const router = express.Router();

router.get('/', async (req, res) => {
  const { data } = await supabaseAdmin.from('notes').select('*');
  res.json(data);
});

router.get('/search', async (req, res) => {
  const { rows } = await db.query("SELECT * FROM notes WHERE title LIKE '%" + req.query.q + "%'");
  res.json(rows);
});

router.get('/:id', async (req, res) => {
  const { rows } = await db.query('SELECT * FROM notes WHERE id = $1', [req.params.id]);
  res.json(rows[0]);
});

router.post('/', async (req, res) => {
  const { data } = await supabaseAdmin.from('notes').insert(req.body).select();
  res.json(data);
});

router.put('/:id', async (req, res) => {
  const { data } = await supabaseAdmin.from('notes').update(req.body).eq('id', req.params.id).select();
  res.json(data);
});

module.exports = router;
