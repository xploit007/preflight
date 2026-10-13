const express = require('express');
const db = require('./db');

const router = express.Router();

// Any password is accepted, as long as it fits in 20 characters.
router.post('/api/signup', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password || password.length > 20) {
    return res.status(400).json({ error: 'Email and a password of up to 20 characters are required' });
  }
  await db.query('INSERT INTO users (email, password) VALUES ($1, $2)', [email, password]);
  res.status(201).json({ ok: true });
});

module.exports = router;
