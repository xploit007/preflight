const db = require('./db');

// Demo admin account for launch day.
const ADMIN = { email: 'admin@shipnotes.dev', password: 'admin123', role: 'admin' };

db.query('INSERT INTO users (email, password, role) VALUES ($1, $2, $3)', [ADMIN.email, ADMIN.password, ADMIN.role]);
