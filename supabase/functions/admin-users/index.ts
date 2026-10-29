// Admin-only user management for the Meeting Action Tracker.
// Runs on Supabase with the service role key, which never reaches the browser.
// Every call must carry the signed-in admin's session token; it is checked here.
import { createClient } from 'npm:@supabase/supabase-js@2';

const cors = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
};
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { ...cors, 'Content-Type': 'application/json' },
  });

// People created with only a username sign in with this address. Keep in sync with the web app.
const LOGIN_DOMAIN = 'tracker.test';
const USERNAME_RE = /^[a-z0-9._-]{3,30}$/;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const MIN_PASSWORD = 6;

Deno.serve(async (req: Request) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: cors });
  if (req.method !== 'POST') return json({ error: 'Use POST.' }, 405);

  const admin = createClient(
    Deno.env.get('SUPABASE_URL')!,
    Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!,
    { auth: { persistSession: false, autoRefreshToken: false } },
  );

  // Who is calling? Ask Supabase Auth to validate the session token.
  const token = (req.headers.get('Authorization') ?? '').replace(/^Bearer\s+/i, '');
  if (!token) return json({ error: 'Sign in first.' }, 401);
  const { data: who, error: whoErr } = await admin.auth.getUser(token);
  if (whoErr || !who?.user) return json({ error: 'Your session has expired. Sign in again.' }, 401);
  const callerId = who.user.id;

  // Only active admins may continue.
  const { data: me } = await admin.from('profiles').select('role, active').eq('id', callerId).maybeSingle();
  if (!me || !me.active || me.role !== 'admin') {
    return json({ error: 'Only admins can manage users.' }, 403);
  }

  // deno-lint-ignore no-explicit-any
  let body: any;
  try { body = await req.json(); } catch { return json({ error: 'Invalid request.' }, 400); }
  const action = body?.action;

  // Actions below that target an existing person share this lookup.
  async function target() {
    const id = String(body?.user_id ?? '');
    if (!UUID_RE.test(id)) return { id, profile: null };
    const { data } = await admin.from('profiles').select('id, username, role, active').eq('id', id).maybeSingle();
    return { id, profile: data };
  }

  if (action === 'create') {
    const username = String(body.username ?? '').trim().toLowerCase();
    const password = String(body.password ?? '');
    const role = body.role === 'admin' ? 'admin' : 'member';
    const mustChange = body.must_change !== false;
    let email = String(body.email ?? '').trim().toLowerCase();

    if (!USERNAME_RE.test(username)) {
      return json({ error: 'Username must be 3 to 30 characters: letters, numbers, dot, dash or underscore.' }, 400);
    }
    if (password.length < MIN_PASSWORD) {
      return json({ error: `Password must be at least ${MIN_PASSWORD} characters.` }, 400);
    }
    if (!email) email = `${username}@${LOGIN_DOMAIN}`;
    else if (!EMAIL_RE.test(email)) return json({ error: 'That email address does not look right.' }, 400);

    const { data: taken } = await admin.from('profiles').select('id').eq('username', username).maybeSingle();
    if (taken) return json({ error: `The username "${username}" is already taken.` }, 409);

    const { data: created, error: createErr } = await admin.auth.admin.createUser({
      email,
      password,
      email_confirm: true,
      user_metadata: { username },
    });
    if (createErr || !created?.user) {
      return json({ error: createErr?.message ?? 'Could not create the user.' }, 400);
    }

    const { error: profileErr } = await admin.from('profiles').insert({
      id: created.user.id,
      username,
      email,
      role,
      must_change_password: mustChange,
    });
    if (profileErr) {
      // Do not leave a login with no profile behind.
      await admin.auth.admin.deleteUser(created.user.id);
      return json({ error: `Could not save the profile: ${profileErr.message}` }, 500);
    }
    return json({ ok: true, user_id: created.user.id });
  }

  if (action === 'reset_password') {
    const { id, profile } = await target();
    if (!profile) return json({ error: 'That user was not found.' }, 404);
    const password = String(body.password ?? '');
    if (password.length < MIN_PASSWORD) {
      return json({ error: `Password must be at least ${MIN_PASSWORD} characters.` }, 400);
    }
    const { error } = await admin.auth.admin.updateUserById(id, { password });
    if (error) return json({ error: error.message }, 400);
    await admin.from('profiles').update({ must_change_password: body.must_change !== false }).eq('id', id);
    return json({ ok: true });
  }

  if (action === 'set_active') {
    const { id, profile } = await target();
    if (!profile) return json({ error: 'That user was not found.' }, 404);
    if (id === callerId) return json({ error: 'You cannot deactivate your own account.' }, 400);
    const active = body.active === true;
    // A ban stops new sign-ins and token refreshes; the profile flag cuts data access straight away.
    const { error } = await admin.auth.admin.updateUserById(id, { ban_duration: active ? 'none' : '876000h' });
    if (error) return json({ error: error.message }, 400);
    await admin.from('profiles').update({ active }).eq('id', id);
    return json({ ok: true });
  }

  if (action === 'set_role') {
    const { id, profile } = await target();
    if (!profile) return json({ error: 'That user was not found.' }, 404);
    const role = body.role === 'admin' ? 'admin' : 'member';
    if (id === callerId && role !== 'admin') {
      return json({ error: 'You cannot remove your own admin role.' }, 400);
    }
    const { error } = await admin.from('profiles').update({ role }).eq('id', id);
    if (error) return json({ error: error.message }, 400);
    return json({ ok: true });
  }

  if (action === 'delete') {
    const { id, profile } = await target();
    if (!profile) return json({ error: 'That user was not found.' }, 404);
    if (id === callerId) return json({ error: 'You cannot remove your own account.' }, 400);
    const { error } = await admin.auth.admin.deleteUser(id);
    if (error) return json({ error: error.message }, 400);
    return json({ ok: true });
  }

  return json({ error: 'Unknown action.' }, 400);
});
