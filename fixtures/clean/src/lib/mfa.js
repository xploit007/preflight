import { supabase } from './supabase.js';

// Two-factor sign-in with an authenticator app (TOTP), through Supabase Auth MFA.
export async function enrollAuthenticator() {
  const { data, error } = await supabase.auth.mfa.enroll({ factorType: 'totp' });
  if (error) throw error;
  return data; // show data.totp.qr_code, then verify with the first code
}

export async function verifyAuthenticator(factorId, code) {
  const { data, error } = await supabase.auth.mfa.challengeAndVerify({ factorId, code });
  if (error) throw error;
  return data;
}
