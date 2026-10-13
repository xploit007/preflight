export default function Signup() {
  return (
    <form method="post" action="/api/signup">
      <label htmlFor="email">Email</label>
      <input id="email" name="email" type="email" />
      <label htmlFor="password">Password</label>
      <input id="password" name="password" type="password" maxLength={20} />
      <label>
        <input type="checkbox" name="newsletter" defaultChecked /> Send me product news and offers
      </label>
      <button type="submit">Create account</button>
    </form>
  );
}
