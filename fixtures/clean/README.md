# ShipNotes (done right)

The same app as `fixtures/vulnerable`, written the way preflight wants it: secrets only in
environment variables, Supabase RLS with owner-only policies, auth and rate limits on every
API route, validated input, signed webhooks, server-side prices, security headers and
accessible markup. preflight should report no critical or high failures here.
