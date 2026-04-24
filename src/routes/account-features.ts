/**
 * Account-feature routes mounted at /account/*
 *
 * Each route validates the session via SESSION KV directly, then proxies
 * to data.xaostech.io with the user_id scoped in. Account workers/pages
 * call these via the shared /api/[...path].ts catch-all proxy.
 */

import { Hono } from 'hono';
import { fetchData, ensureDataAccessOrReject } from '../lib/data-proxy';

export const accountFeaturesRouter = new Hono();

/**
 * Pull session_id from cookie or Authorization header, look up SESSION KV,
 * return { userId } or a 401 Response.
 */
async function resolveUser(c: any): Promise<{ userId: string } | Response> {
  const cookie = c.req.header('Cookie') || '';
  const m = cookie.match(/session_id=([^;]+)/);
  const sid = m ? m[1] : (c.req.header('Authorization')?.replace('Bearer ', '') || c.req.query('session_id'));
  if (!sid) return c.json({ error: 'Unauthorized' }, 401);

  const kv = c.env.SESSIONS_KV;
  if (!kv) return c.json({ error: 'SESSION KV not configured' }, 501);

  const raw = await kv.get(sid);
  if (!raw) return c.json({ error: 'Invalid session' }, 401);

  try {
    const parsed = JSON.parse(raw);
    const userId = parsed.userId || parsed.user_id;
    if (!userId) return c.json({ error: 'Session missing userId' }, 401);
    return { userId };
  } catch {
    return c.json({ error: 'Corrupt session' }, 500);
  }
}

const isResponse = (v: any): v is Response => v && typeof v.status === 'number' && typeof (v as any).headers?.get === 'function';

/**
 * Proxy a JSON response from data.xaostech.io straight back to caller.
 */
async function proxyData(c: any, path: string, init: RequestInit = {}): Promise<Response> {
  const reject = ensureDataAccessOrReject(c);
  if (reject) return reject;
  const res = await fetchData(c, path, init);
  const body = await res.text();
  return new Response(body, {
    status: res.status,
    headers: { 'Content-Type': res.headers.get('Content-Type') || 'application/json' },
  });
}

// ---- API Keys ----
accountFeaturesRouter.get('/api-keys', async (c: any) => {
  const u = await resolveUser(c);
  if (isResponse(u)) return u;
  return proxyData(c, `/account/api-keys?user_id=${encodeURIComponent(u.userId)}`);
});

accountFeaturesRouter.post('/api-keys', async (c: any) => {
  const u = await resolveUser(c);
  if (isResponse(u)) return u;
  const body = await c.req.json().catch(() => ({}));
  const { name, scopes } = body || {};
  if (!name || name.length < 1 || name.length > 100) return c.json({ error: 'Invalid key name' }, 400);

  // Generate API key server-side here (so the plaintext never leaves api worker)
  const id = crypto.randomUUID();
  const rand = crypto.getRandomValues(new Uint8Array(32));
  const key = 'xk_' + Array.from(rand).map(b => b.toString(16).padStart(2, '0')).join('');
  const prefix = key.slice(0, 12);
  const hashBuf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(key));
  const hash = Array.from(new Uint8Array(hashBuf)).map(b => b.toString(16).padStart(2, '0')).join('');

  const res = await fetchData(c, '/account/api-keys', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ id, user_id: u.userId, name, key_prefix: prefix, key_hash: hash, scopes }),
  });
  if (!res.ok) {
    const text = await res.text();
    return new Response(text, { status: res.status, headers: { 'Content-Type': 'application/json' } });
  }
  return c.json({ id, key, name, key_prefix: prefix, scopes: scopes || ['read', 'write'] }, 201);
});

accountFeaturesRouter.get('/api-keys/:id', async (c: any) => {
  const u = await resolveUser(c);
  if (isResponse(u)) return u;
  return proxyData(c, `/account/api-keys/${c.req.param('id')}?user_id=${encodeURIComponent(u.userId)}`);
});

accountFeaturesRouter.patch('/api-keys/:id', async (c: any) => {
  const u = await resolveUser(c);
  if (isResponse(u)) return u;
  const body = await c.req.text();
  return proxyData(c, `/account/api-keys/${c.req.param('id')}?user_id=${encodeURIComponent(u.userId)}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body,
  });
});

accountFeaturesRouter.delete('/api-keys/:id', async (c: any) => {
  const u = await resolveUser(c);
  if (isResponse(u)) return u;
  return proxyData(c, `/account/api-keys/${c.req.param('id')}?user_id=${encodeURIComponent(u.userId)}`, { method: 'DELETE' });
});

// ---- Profile (extended) ----
accountFeaturesRouter.get('/profile/posts', async (c: any) => {
  const u = await resolveUser(c);
  if (isResponse(u)) return u;
  const limit = c.req.query('limit') || '10';
  return proxyData(c, `/account/profile/posts?user_id=${encodeURIComponent(u.userId)}&limit=${limit}`);
});

accountFeaturesRouter.get('/profile/friends', async (c: any) => {
  const u = await resolveUser(c);
  if (isResponse(u)) return u;
  const limit = c.req.query('limit') || '10';
  return proxyData(c, `/account/profile/friends?user_id=${encodeURIComponent(u.userId)}&limit=${limit}`);
});

accountFeaturesRouter.get('/profile/feed', async (c: any) => {
  const u = await resolveUser(c);
  if (isResponse(u)) return u;
  const ids = c.req.query('user_ids') || '';
  const limit = c.req.query('limit') || '20';
  return proxyData(c, `/account/profile/feed?user_ids=${encodeURIComponent(ids)}&limit=${limit}`);
});

accountFeaturesRouter.get('/profile/settings', async (c: any) => {
  const u = await resolveUser(c);
  if (isResponse(u)) return u;
  return proxyData(c, `/account/profile/settings?user_id=${encodeURIComponent(u.userId)}`);
});

accountFeaturesRouter.patch('/profile', async (c: any) => {
  const u = await resolveUser(c);
  if (isResponse(u)) return u;
  const body = await c.req.json().catch(() => ({}));
  // /users/:userId already exists on data worker; uses ACCOUNT_DB
  return proxyData(c, `/users/${encodeURIComponent(u.userId)}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
});

// ---- GDPR ----
accountFeaturesRouter.post('/gdpr/delete-request', async (c: any) => {
  const u = await resolveUser(c);
  if (isResponse(u)) return u;
  const body = await c.req.json().catch(() => ({}));
  return proxyData(c, '/account/gdpr/deletions', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ user_id: u.userId, reason: body.reason }),
  });
});

// ---- Family ----
accountFeaturesRouter.get('/family/children', async (c: any) => {
  const u = await resolveUser(c);
  if (isResponse(u)) return u;
  return proxyData(c, `/account/family/children?parent_id=${encodeURIComponent(u.userId)}`);
});

accountFeaturesRouter.get('/family/children/:id', async (c: any) => {
  const u = await resolveUser(c);
  if (isResponse(u)) return u;
  return proxyData(c, `/account/family/children/${c.req.param('id')}?parent_id=${encodeURIComponent(u.userId)}`);
});

accountFeaturesRouter.get('/family/approvals', async (c: any) => {
  const u = await resolveUser(c);
  if (isResponse(u)) return u;
  const limit = c.req.query('limit') || '20';
  return proxyData(c, `/account/family/approvals?parent_id=${encodeURIComponent(u.userId)}&limit=${limit}`);
});

accountFeaturesRouter.post('/family/add-child', async (c: any) => {
  const u = await resolveUser(c);
  if (isResponse(u)) return u;

  // Accept either JSON or form data from account-side handler.
  const ct = c.req.header('Content-Type') || '';
  let body: any = {};
  if (ct.includes('application/json')) {
    body = await c.req.json().catch(() => ({}));
  } else {
    const form = await c.req.formData();
    form.forEach((v: any, k: string) => { body[k] = typeof v === 'string' ? v : v?.toString?.() || ''; });
  }

  const password = body.password;
  if (!body.child_name || !body.username || !password) {
    return c.json({ error: 'child_name, username, password required' }, 400);
  }

  // Hash the password (SHA-256 with salt) — matches account/login.ts format
  const saltBytes = crypto.getRandomValues(new Uint8Array(16));
  const salt = Array.from(saltBytes).map(b => b.toString(16).padStart(2, '0')).join('');
  const hashBuf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(salt + password));
  const hash = Array.from(new Uint8Array(hashBuf)).map(b => b.toString(16).padStart(2, '0')).join('');
  const password_hash = `$sha256$${salt}$${hash}`;

  return proxyData(c, '/account/family/children', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      parent_id: u.userId,
      child_id: crypto.randomUUID(),
      child_name: body.child_name,
      username: body.username,
      email: body.email || null,
      password_hash,
      birth_year: body.birth_year ? parseInt(body.birth_year) : null,
      content_filter_level: body.content_filter_level || 'strict',
      daily_time_limit: body.daily_limit ? parseInt(body.daily_limit) : 60,
      weekly_time_limit: body.weekly_limit ? parseInt(body.weekly_limit) : 420,
      can_post_content: body.can_post_content === 'on' || body.can_post_content === true,
      can_comment: body.can_comment === 'on' || body.can_comment === true,
      require_approval_for_posts: body.require_approval_for_posts === 'on' || body.require_approval_for_posts === true,
    }),
  });
});

accountFeaturesRouter.post('/family/deny/:id', async (c: any) => {
  const u = await resolveUser(c);
  if (isResponse(u)) return u;
  return proxyData(c, `/account/family/approvals/${c.req.param('id')}/deny?parent_id=${encodeURIComponent(u.userId)}`, { method: 'POST' });
});

accountFeaturesRouter.post('/family/approve/:id', async (c: any) => {
  const u = await resolveUser(c);
  if (isResponse(u)) return u;
  return proxyData(c, `/account/family/approvals/${c.req.param('id')}/approve?parent_id=${encodeURIComponent(u.userId)}`, { method: 'POST' });
});

// ---- Service Accounts ----
accountFeaturesRouter.get('/service-accounts', async (c: any) => {
  const u = await resolveUser(c);
  if (isResponse(u)) return u;
  return proxyData(c, `/account/service-accounts?user_id=${encodeURIComponent(u.userId)}`);
});

accountFeaturesRouter.post('/service-accounts', async (c: any) => {
  const u = await resolveUser(c);
  if (isResponse(u)) return u;
  const body = await c.req.json().catch(() => ({}));
  const { name, description, scopes } = body || {};
  if (!name) return c.json({ error: 'name required' }, 400);

  const id = crypto.randomUUID();
  const rand = crypto.getRandomValues(new Uint8Array(32));
  const token = 'sa_' + Array.from(rand).map(b => b.toString(16).padStart(2, '0')).join('');
  const hashBuf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(token));
  const token_hash = Array.from(new Uint8Array(hashBuf)).map(b => b.toString(16).padStart(2, '0')).join('');

  const res = await fetchData(c, '/account/service-accounts', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ id, owner_id: u.userId, name, description, scopes, token_hash }),
  });
  if (!res.ok) {
    const text = await res.text();
    return new Response(text, { status: res.status, headers: { 'Content-Type': 'application/json' } });
  }
  return c.json({ id, token, name, description, scopes }, 201);
});
