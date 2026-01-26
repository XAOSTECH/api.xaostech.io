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

// Register a new user (email + username + password) - uses DATA service
accountRouter.post('/register', async (c: any) => {
  const dataService = c.env.DATA;
  if (!dataService) return c.json({ error: 'DATA service not configured' }, 501);

  const body = await c.req.json().catch(() => ({}));
  const { email, username, password } = body || {};
  if (!email || !username || !password) return c.json({ error: 'email, username and password required' }, 400);

  try {
    // Check if user exists by email (need to add this route to data worker)
    const checkResp = await dataService.fetch(`https://data.xaostech.io/users/email/${encodeURIComponent(email)}`);
    const checkData = await checkResp.json() as { found?: boolean };
    if (checkData.found) return c.json({ error: 'User with that email already exists' }, 409);

    const passwordHash = await hashPassword(password);
    const userId = crypto.randomUUID();

    const createResp = await dataService.fetch('https://data.xaostech.io/users', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        id: userId,
        email,
        username,
        password_hash: passwordHash,
      }),
    });

    if (!createResp.ok) {
      const err = await createResp.json() as { error?: string };
      return c.json({ error: err.error || 'Registration failed' }, 500);
    }

    return c.json({ success: true, id: userId }, 201);
  } catch (err: any) {
    console.error('Register error', err);
    return c.json({ error: 'Registration failed' }, 500);
  }
});

// Login with email + password -> create session and return session cookie
accountRouter.post('/login', async (c: any) => {
  const dataService = c.env.DATA;
  const sessionKv = c.env.SESSION;
  if (!dataService) return c.json({ error: 'DATA service not configured' }, 501);
  if (!sessionKv) return c.json({ error: 'SESSION KV not configured' }, 501);

  const { email, password } = await c.req.json().catch(() => ({}));
  if (!email || !password) return c.json({ error: 'email and password required' }, 400);

  try {
    // Fetch user by email from DATA worker
    const userResp = await dataService.fetch(`https://data.xaostech.io/users/email/${encodeURIComponent(email)}`);
    const userData = await userResp.json() as { found?: boolean; user?: any };
    
    if (!userData.found || !userData.user) return c.json({ error: 'Invalid credentials' }, 401);
    const user = userData.user;

    const ok = await verifyHash(password, user.password_hash || '');
    if (!ok) return c.json({ error: 'Invalid credentials' }, 401);

    const sessionId = crypto.randomUUID();
    await sessionKv.put(sessionId, JSON.stringify({ userId: user.id }), { expirationTtl: 60 * 60 * 24 * 7 });

    const cookieDomain = c.env.COOKIE_DOMAIN || '.xaostech.io';
    const sessionCookie = `session_id=${sessionId}; Domain=${cookieDomain}; Path=/; Max-Age=${60 * 60 * 24 * 7}; HttpOnly; Secure; SameSite=Lax`;

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
    
    // Fetch user info from DATA worker
    const dataService = c.env.DATA;
    if (!dataService) return c.json({ userId, sessionId: token, isAdmin: false });
    
    const userResp = await dataService.fetch(`https://data.xaostech.io/users/${userId}`);
    const userData = await userResp.json() as { user?: any };
    const user = userData.user;
    
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
  
  // Fetch user from DATA worker
  const dataService = c.env.DATA;
  if (!dataService) return c.json({ error: 'DATA service not configured' }, 501);
  
  const userResp = await dataService.fetch(`https://data.xaostech.io/users/${userId}`);
  const userData = await userResp.json() as { user?: any; error?: string };
  
  if (!userData.user) return c.json({ error: 'User not found' }, 404);
  return c.json({ user: userData.user });
});
