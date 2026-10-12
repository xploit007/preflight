const express = require('express');
const cors = require('cors');
const notes = require('./routes/notes');
const admin = require('./routes/admin');
const auth = require('./auth');
const payments = require('./payments');
const sms = require('./sms');
const chat = require('./chat');
const tools = require('./tools');
const upload = require('./upload');

const app = express();

// Let the frontend (and anything else) call the API with cookies.
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());

app.use('/api/notes', notes);
app.use('/api/admin', admin);
app.post('/api/login', auth.login);
app.post('/api/forgot-password', auth.forgotPassword);
app.post('/api/checkout', payments.checkout);
app.post('/api/stripe/webhook', payments.webhook);
app.post('/api/sms/send', sms.send);
app.post('/api/chat', chat.reply);
app.get('/api/tools/preview', tools.preview);
app.get('/api/tools/convert', tools.convert);
app.post('/api/tools/calc', tools.calc);
app.get('/api/files', tools.download);
app.get('/api/go', tools.go);
app.post('/api/upload', upload.single('file'), (req, res) => res.json({ path: req.file.path }));

app.use((err, req, res, next) => {
  res.status(500).json({ error: err.message, stack: err.stack });
});

app.listen(process.env.PORT || 3000);
module.exports = app;
