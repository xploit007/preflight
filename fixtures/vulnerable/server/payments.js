const Stripe = require('stripe');

const stripe = Stripe('sk_live_51PreflightFakeKeyDoNotUse000000000000');

async function checkout(req, res) {
  const { email } = req.body;
  const intent = await stripe.paymentIntents.create({
    amount: req.body.amount,
    currency: 'usd',
    receipt_email: email,
  });
  res.json({ clientSecret: intent.client_secret });
}

async function webhook(req, res) {
  const event = req.body;
  if (event.type === 'payment_intent.succeeded') {
    // mark the order as paid
  }
  res.json({ received: true });
}

module.exports = { checkout, webhook };
