const twilio = require('twilio');

const client = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);

async function send(req, res) {
  const { phone, message } = req.body;
  await client.messages.create({
    to: phone,
    from: '+15555550100',
    body: message,
  });
  res.json({ sent: true });
}

module.exports = { send };
