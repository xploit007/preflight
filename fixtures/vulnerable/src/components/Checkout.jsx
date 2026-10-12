import { useState } from 'react';

const PRICE = 49;

export default function Checkout() {
  const [coupon, setCoupon] = useState('');
  const total = coupon === 'LAUNCH100' ? 0.5 : PRICE;

  async function pay() {
    const res = await fetch('/api/checkout', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ amount: total * 100, email: 'me@example.com' }),
    });
    const { clientSecret } = await res.json();
    console.log('pay with', clientSecret);
  }

  return (
    <div>
      <input value={coupon} onChange={(e) => setCoupon(e.target.value)} />
      <button onClick={pay}>Pay ${total}</button>
    </div>
  );
}
