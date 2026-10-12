import express from 'express';
import helmet from 'helmet';
import { rateLimit } from 'express-rate-limit';
import notes from './routes/notes.js';
import admin from './routes/admin.js';
import { requireUser, requireAdmin } from './auth.js';
import { checkout, webhook } from './payments.js';
import { reply } from './chat.js';

const app = express();

app.use(helmet());
app.use('/api', rateLimit({ windowMs: 60_000, limit: 100, standardHeaders: 'draft-8', legacyHeaders: false }));

// Stripe signs the raw body, so the webhook route is registered before express.json().
app.post('/api/stripe/webhook', express.raw({ type: 'application/json' }), webhook);
app.use(express.json({ limit: '100kb' }));

app.use('/api/notes', requireUser, notes);
app.use('/api/admin', requireUser, requireAdmin, admin);
app.post('/api/checkout', requireUser, checkout);
app.post('/api/chat', requireUser, rateLimit({ windowMs: 60_000, limit: 10 }), reply);

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'Internal error' });
});

export default app;
