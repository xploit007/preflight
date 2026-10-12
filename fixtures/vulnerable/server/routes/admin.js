const express = require('express');
const db = require('../db');

const router = express.Router();

router.get('/users', async (req, res) => {
  const { rows } = await db.query('SELECT id, email, role FROM users');
  res.json(rows);
});

router.delete('/users/:id', async (req, res) => {
  await db.query('DELETE FROM users WHERE id = $1', [req.params.id]);
  res.json({ ok: true });
});

module.exports = router;
