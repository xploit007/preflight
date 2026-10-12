import Stripe from 'stripe';
import { z } from 'zod';

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
// Prices live on the server as Stripe Price IDs. The browser only says which plan it wants.
const PRICES = { pro: process.env.STRIPE_PRICE_PRO };
const CheckoutInput = z.object({ plan: z.enum(['pro']) });

export async function checkout(req, res) {
  const { plan } = CheckoutInput.parse(req.body);
  const session = await stripe.checkout.sessions.create({
    mode: 'subscription',
    line_items: [{ price: PRICES[plan], quantity: 1 }],
    customer_email: req.user.email,
    client_reference_id: req.user.id,
    success_url: `${process.env.APP_URL}/billing?status=success`,
    cancel_url: `${process.env.APP_URL}/billing`,
  });
  res.json({ url: session.url });
}

export async function webhook(req, res) {
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, req.headers['stripe-signature'], process.env.STRIPE_WEBHOOK_SECRET);
  } catch {
    return res.status(400).send('Invalid signature');
  }
  if (event.type === 'checkout.session.completed') {
    // Provision the plan for event.data.object.client_reference_id (idempotent on event.id).
  }
  res.json({ received: true });
}
