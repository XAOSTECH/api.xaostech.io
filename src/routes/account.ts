import { Hono } from 'hono';
import { AuthContext } from '../middleware/auth';

export const accountRouter = new Hono();

function toBase64(b: ArrayBuffer) {
  const bytes = new Uint8Array(b);
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}

function fromBase64(s: string) {
  const binary = atob(s);
  const len = binary.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

async function hashPassword(password: string, salt?: string) {
  const enc = new TextEncoder();
  const saltStr = salt || toBase64(crypto.getRandomValues(new Uint8Array(16)).buffer);
  const key = await crypto.subtle.importKey('raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveBits']);
  const derived = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: enc.encode(saltStr), iterations: 100_000, hash: 'SHA-256' },
    key,
    256
  );
  return `${saltStr}:${toBase64(derived)}`;
}

function verifyHash(password: string, stored: string) {
  const [salt, hash] = stored.split(':');
  return hashPassword(password, salt).then(h => h === stored);
}

// Register a new user (email + username + password)
accountRouter.post('/register', async (c: any) => {
  const db = c.env.DB;
  if (!db) return c.json({ error: 'DB not configured' }, 501);

  const body = await c.req.json().catch(() => ({}));
  const { email, username, password } = body || {};
  if (!email || !username || !password) return c.json({ error: 'email, username and password required' }, 400);

  try {
    const existing = await db.prepare('SELECT id FROM users WHERE email = ?').bind(email).first();
    if (existing && (existing as any).id) return c.json({ error: 'User with that email already exists' }, 409);

    const passwordHash = await hashPassword(password);
    const userId = crypto.randomUUID();

    await db.prepare('INSERT INTO users (id, email, username, password_hash, created_at, last_login) VALUES (?, ?, ?, ?, datetime("now"), datetime("now"))')
      .bind(userId, email, username, passwordHash).run();

    return c.json({ success: true, id: userId }, 201);
  } catch (err: any) {
    console.error('Register error', err);
    return c.json({ error: 'Registration failed' }, 500);
  }
});

// Login with email + password -> create session and return session cookie
accountRouter.post('/login', async (c: any) => {
  const db = c.env.DB;
  const sessionKv = c.env.SESSION;
  if (!db) return c.json({ error: 'DB not configured' }, 501);
  if (!sessionKv) return c.json({ error: 'SESSION KV not configured' }, 501);

  const { email, password } = await c.req.json().catch(() => ({}));
  if (!email || !password) return c.json({ error: 'email and password required' }, 400);

  try {
    const row = await db.prepare('SELECT id, password_hash FROM users WHERE email = ?').bind(email).first();
    if (!row || !(row as any).id) return c.json({ error: 'Invalid credentials' }, 401);
    const user = row as any;

    const ok = await verifyHash(password, user.password_hash || '');
    if (!ok) return c.json({ error: 'Invalid credentials' }, 401);

    const sessionId = crypto.randomUUID();
    await sessionKv.put(sessionId, JSON.stringify({ userId: user.id }), { expirationTtl: 60 * 60 * 24 * 7 });

    const sessionCookie = `session_id=${sessionId}; Path=/; Max-Age=${60 * 60 * 24 * 7}; HttpOnly; Secure; SameSite=Lax`;

    return new Response(JSON.stringify({ success: true, id: user.id }), { status: 200, headers: { 'Set-Cookie': sessionCookie, 'Content-Type': 'application/json' } });
  } catch (err: any) {
    console.error('Login error', err);
    return c.json({ error: 'Login failed' }, 500);
  }
});

// Verify session token (POST { token, tokenType }) - used by other services for token verification
accountRouter.post('/verify', async (c: any) => {
  const body = await c.req.json().catch(() => ({}));
  const { token, tokenType } = body || {};
  if (!token) return c.json({ error: 'token required' }, 400);

  if (tokenType === 'session' || !tokenType) {
    const kv = c.env.SESSION;
    if (!kv) return c.json({ error: 'SESSION KV not configured' }, 501);

    const raw = await kv.get(token);
    if (!raw) return c.json({ error: 'invalid_session' }, 401);
    const parsed = JSON.parse(raw);
    const userId = parsed.userId;
    // Optionally fetch user info
    const row = await c.env.DB.prepare('SELECT id, email, username, is_admin FROM users WHERE id = ?').bind(userId).first();
    const user = row ? (row as any) : null;
    return c.json({ userId, sessionId: token, isAdmin: user?.is_admin || false });
  }

  // For bearer token, we don't support it yet
  return c.json({ error: 'unsupported_token_type' }, 400);
});

// Get current user info from session cookie or Authorization header
accountRouter.get('/me', async (c: any) => {
  const cookie = c.req.header('Cookie') || '';
  const m = cookie.match(/session_id=([^;]+)/);
  const sid = m ? m[1] : null;
  const sessionKv = c.env.SESSION;
  if (!sessionKv) return c.json({ error: 'SESSION KV not configured' }, 501);

  const token = sid || c.req.query('session_id') || c.req.header('Authorization')?.replace('Bearer ', '');
  if (!token) return c.json({ error: 'Not authenticated' }, 401);

  const raw = await sessionKv.get(token);
  if (!raw) return c.json({ error: 'Invalid session' }, 401);
  const obj = JSON.parse(raw);
  const userId = obj.userId;
  const row = await c.env.DB.prepare('SELECT id, username, email, avatar_url, is_admin, created_at FROM users WHERE id = ?').bind(userId).first();
  if (!row) return c.json({ error: 'User not found' }, 404);
  const user = row as any;
  return c.json({ user });
});
