const { Resend } = require('resend');
const db = require('./db');

const resend = new Resend(process.env.RESEND_API_KEY);

// Every Monday: product news and a discount, to every user who ever signed up.
async function sendWeeklyNewsletter() {
  const { rows } = await db.query('SELECT email FROM users');
  for (const user of rows) {
    await resend.emails.send({
      from: 'ShipNotes <news@shipnotes.dev>',
      to: user.email,
      subject: 'This week at ShipNotes: new templates and 20% off Pro',
      html: '<h1>New this week</h1><p>Templates are here, and Pro is 20% off until Friday.</p>',
    });
  }
}

module.exports = { sendWeeklyNewsletter };
