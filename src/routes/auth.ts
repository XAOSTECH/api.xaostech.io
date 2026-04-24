import { Hono } from 'hono';
import { z } from 'zod';

export const authRouter = new Hono();

// Validation schemas
const RegisterSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8).regex(/[A-Z]/, 'Password must contain uppercase').regex(/[0-9]/, 'Password must contain number'),
  username: z.string().min(3).max(30).regex(/^[a-zA-Z0-9_-]+$/, 'Username must be alphanumeric'),
});

const LoginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1),
});

// Password hashing using Web Crypto API
async function hashPassword(password: string, salt?: string): Promise<{ hash: string; salt: string }> {
  const encoder = new TextEncoder();
  const useSalt = salt || crypto.randomUUID().replace(/-/g, '');
  const data = encoder.encode(password + useSalt);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hash = Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
  return { hash, salt: useSalt };
}

async function verifyPassword(password: string, storedHash: string, salt: string): Promise<boolean> {
  const { hash } = await hashPassword(password, salt);
  return hash === storedHash;
}

// Generate email verification token
function generateVerificationToken(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// Helper to validate return_to URLs (must be same-site)
function isValidReturnTo(url: string): boolean {
  if (!url) return false;
  try {
    const parsed = new URL(url);
    return parsed.hostname.endsWith('.xaostech.io') || parsed.hostname === 'xaostech.io';
  } catch {
    // Relative URLs are allowed
    return url.startsWith('/');
  }
}

// Redirect /github to /github/login for convenience
authRouter.get('/github', (c: any) => {
  const returnTo = c.req.query('return_to') || '';
  const redirectUrl = returnTo ? `/auth/github/login?return_to=${encodeURIComponent(returnTo)}` : '/auth/github/login';
  return c.redirect(redirectUrl);
});

// GitHub OAuth
authRouter.get('/github/login', (c: any) => {
  const clientId = c.env.GITHUB_OAUTH_CLIENT_ID;
  if (!clientId) return c.json({ error: 'GITHUB_OAUTH_CLIENT_ID not configured' }, 501);

  // Support return_to parameter for post-login redirect
  const returnTo = c.req.query('return_to') || 'https://account.xaostech.io';
  const safeReturnTo = isValidReturnTo(returnTo) ? returnTo : 'https://account.xaostech.io';

  // Optional login hint - suggest a GitHub username to pre-fill
  const loginHint = c.req.query('login') || '';

  const state = crypto.randomUUID();

  // IMPORTANT: redirect_uri MUST always be the canonical account.xaostech.io callback
  // This is what's registered with GitHub OAuth - any other URL will fail
  const redirectUri = 'https://account.xaostech.io/api/auth/github/callback';

  // State cookie for CSRF protection - must be Lax for OAuth redirect to work
  // Also store return_to in state cookie
  const cookieDomain = c.env.COOKIE_DOMAIN || '.xaostech.io';
  const stateCookie = `gh_oauth_state=${state}; Domain=${cookieDomain}; Path=/; Max-Age=300; SameSite=Lax; Secure; HttpOnly`;
  const returnCookie = `gh_return_to=${encodeURIComponent(safeReturnTo)}; Domain=${cookieDomain}; Path=/; Max-Age=300; SameSite=Lax; Secure; HttpOnly`;

  const authUrl = new URL('https://github.com/login/oauth/authorize');
  authUrl.searchParams.set('client_id', clientId);
  authUrl.searchParams.set('redirect_uri', redirectUri);
  authUrl.searchParams.set('scope', 'read:user user:email');
  authUrl.searchParams.set('state', state);

  // If login hint provided, pass to GitHub to pre-fill/suggest the account
  if (loginHint) {
    authUrl.searchParams.set('login', loginHint);
  }

  return new Response(null, {
    status: 302,
    headers: [
      ['Location', authUrl.toString()],
      ['Set-Cookie', stateCookie],
      ['Set-Cookie', returnCookie],
    ]
  });
});

authRouter.get('/github/callback', async (c: any) => {
  const code = c.req.query('code');
  const state = c.req.query('state');
  const clientId = c.env.GITHUB_OAUTH_CLIENT_ID;
  const clientSecret = c.env.GITHUB_OAUTH_CLIENT_SECRET;

  if (!code || !state) return c.json({ error: 'code and state required' }, 400);
  if (!clientId || !clientSecret) return c.json({ error: 'GitHub OAuth secrets not configured' }, 501);

  const cookie = c.req.header('Cookie') || '';
  const cookieMatch = cookie.match(/gh_oauth_state=([^;]+)/);
  const cookieState = cookieMatch ? cookieMatch[1] : null;
  if (!cookieState || cookieState !== state) return c.json({ error: 'Invalid state (possible CSRF)' }, 400);

  // IMPORTANT: redirect_uri MUST match exactly what was sent in login request
  // This is the canonical callback registered with GitHub OAuth
  const redirectUri = 'https://account.xaostech.io/api/auth/github/callback';

  try {
    const tokenResp = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: { 'Accept': 'application/json', 'Content-Type': 'application/json' },
      body: JSON.stringify({ client_id: clientId, client_secret: clientSecret, code, redirect_uri: redirectUri }),
    });
    const tokenJson: any = await tokenResp.json();
    const accessToken = tokenJson.access_token;
    if (!accessToken) return c.json({ error: 'Failed to obtain access token', details: tokenJson.error_description || tokenJson.error }, 502);

    const userResp = await fetch('https://api.github.com/user', { headers: { Authorization: `token ${accessToken}`, 'User-Agent': 'xaostech' } });
    if (!userResp.ok) return c.json({ error: 'Failed to fetch GitHub user' }, 502);
    const ghUser = await userResp.json();

    const emailsResp = await fetch('https://api.github.com/user/emails', { headers: { Authorization: `token ${accessToken}`, 'User-Agent': 'xaostech' } });
    let primaryEmail = null;
    if (emailsResp.ok) {
      const emails = await emailsResp.json();
      const primary = (emails || []).find((e: any) => e.primary && e.verified);
      primaryEmail = primary ? primary.email : (emails && emails[0] && emails[0].email);
    }

    // Use DATA service binding for user database operations (centralized in data worker)
    const dataService = c.env.DATA;
    if (!dataService) return c.json({ error: 'DATA service not configured' }, 501);

    // Look up existing user by GitHub ID via data worker
    const lookupResp = await dataService.fetch(`https://data.xaostech.io/users/github/${ghUser.id.toString()}`);
    const lookupData = await lookupResp.json() as { found?: boolean; user?: any; error?: string };

    if (lookupData.error) {
      return c.json({ error: 'User lookup failed', details: lookupData.error }, 502);
    }

    const existing = lookupData.found ? lookupData.user : null;
    let userId = existing?.id;
    let userRole = existing?.role || 'user';
    let isNewUser = false;
    let currentUsername = existing?.username;
    let currentEmail = existing?.email;
    let currentAvatarUrl = existing?.avatar_url;

    if (userId) {
      // Existing user: ONLY update github_* tracking columns and last_login
      // PRESERVE their custom username and avatar - don't overwrite with GitHub values
      await dataService.fetch(`https://data.xaostech.io/users/${userId}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          github_username: ghUser.login || '',
          github_avatar_url: ghUser.avatar_url || '',
          last_login: true,
        }),
      });
    } else {
      userId = crypto.randomUUID();
      isNewUser = true;
      // New user: set username/avatar from GitHub, also save to github_* columns for restore option
      currentUsername = ghUser.login || '';
      currentEmail = primaryEmail || '';
      currentAvatarUrl = ghUser.avatar_url || '';

      const createResp = await dataService.fetch('https://data.xaostech.io/users', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          id: userId,
          github_id: ghUser.id.toString(),
          username: currentUsername,
          email: currentEmail,
          avatar_url: currentAvatarUrl,
          github_username: ghUser.login || '',
          github_avatar_url: ghUser.avatar_url || '',
          role: 'user',
        }),
      });

      if (!createResp.ok) {
        const err = await createResp.json() as { error?: string };
        return c.json({ error: 'Failed to create user', details: err.error }, 502);
      }
    }

    const sessionKv = c.env.SESSIONS_KV;
    if (!sessionKv) return c.json({ error: 'SESSION KV not configured' }, 501);

    const sessionId = crypto.randomUUID();
    const sessionTtl = 60 * 60 * 24 * 7; // 7 days
    // Store full user data in session for cross-worker access
    // Use the user's ACTUAL username/avatar from DB, not GitHub values (for existing users)
    const sessionData = {
      id: userId,
      userId,
      username: currentUsername || ghUser.login || '',
      email: currentEmail || primaryEmail || '',
      avatar_url: currentAvatarUrl || ghUser.avatar_url || '',
      github_id: ghUser.id.toString(),
      role: userRole,
      isNewUser,
      expires: Date.now() + (sessionTtl * 1000),
    };
    await sessionKv.put(sessionId, JSON.stringify(sessionData), { expirationTtl: sessionTtl });

    // Cookie attributes from env vars for cross-subdomain sharing
    const cookieDomain = c.env.COOKIE_DOMAIN || '.xaostech.io';
    const cookieSameSite = c.env.COOKIE_SAME_SITE || 'Lax';
    const sessionCookie = `session_id=${sessionId}; Domain=${cookieDomain}; Path=/; Max-Age=${60 * 60 * 24 * 7}; HttpOnly; Secure; SameSite=${cookieSameSite}`;

    // Get return_to from cookie, default to account.xaostech.io
    const returnToMatch = cookie.match(/gh_return_to=([^;]+)/);
    const returnTo = returnToMatch ? decodeURIComponent(returnToMatch[1]) : 'https://account.xaostech.io';
    const safeReturnTo = isValidReturnTo(returnTo) ? returnTo : 'https://account.xaostech.io';

    // Clear the return_to cookie
    const clearReturnCookie = `gh_return_to=; Domain=${cookieDomain}; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`;

    return new Response(null, {
      status: 302,
      headers: [
        ['Location', safeReturnTo],
        ['Set-Cookie', sessionCookie],
        ['Set-Cookie', clearReturnCookie],
      ]
    });
  } catch (err: any) {
    console.error('GitHub callback error', err);
    return c.json({ error: 'GitHub OAuth failed', message: err?.message || String(err) }, 500);
  }
});

authRouter.post('/logout', async (c: any) => {
  try {
    const sessionKv = c.env.SESSIONS_KV;
    if (sessionKv && c.req.header('Cookie')) {
      const m = c.req.header('Cookie')!.match(/session_id=([^;]+)/);
      const sid = m ? m[1] : null;
      if (sid) await sessionKv.delete(sid);
    }
    // Must include Domain to delete the cross-subdomain cookie
    const cookieDomain = c.env.COOKIE_DOMAIN || '.xaostech.io';
    return new Response(null, { status: 302, headers: { Location: '/', 'Set-Cookie': `session_id=deleted; Domain=${cookieDomain}; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax` } });
  } catch (err: any) {
    console.error('Logout error', err);
    return c.json({ error: 'Logout failed' }, 500);
  }
});

// Get current user from session (used by frontends to check auth status)
authRouter.get('/me', async (c: any) => {
  const cookie = c.req.header('Cookie') || '';
  const sessionMatch = cookie.match(/session_id=([^;]+)/);
  const sessionId = sessionMatch ? sessionMatch[1] : null;

  if (!sessionId) {
    return c.json({ authenticated: false }, 401);
  }

  try {
    const sessionKv = c.env.SESSIONS_KV;
    if (!sessionKv) {
      return c.json({ authenticated: false, error: 'SESSION KV not configured' }, 500);
    }

    const sessionData = await sessionKv.get(sessionId);
    if (!sessionData) {
      return c.json({ authenticated: false, error: 'Session not found' }, 401);
    }

    const session = JSON.parse(sessionData);
    const userId = session.userId;

    // Fetch full user data from DB
    const db = c.env.DB;
    if (!db) {
      return c.json({ authenticated: true, userId, ...session });
    }

    const user = await db.prepare(
      'SELECT id, username, email, avatar_url, created_at, last_login FROM users WHERE id = ?'
    ).bind(userId).first();

    if (!user) {
      return c.json({ authenticated: false, error: 'User not found' }, 401);
    }

    return c.json({
      authenticated: true,
      id: user.id,
      username: user.username,
      email: user.email,
      avatar_url: user.avatar_url,
      created_at: user.created_at,
      last_login: user.last_login,
    });
  } catch (err: any) {
    console.error('Me endpoint error:', err);
    return c.json({ authenticated: false, error: 'Failed to fetch user' }, 500);
  }
});

// ============ EMAIL/PASSWORD AUTH ============
// Fallback for users without GitHub accounts

// POST /register - Create account with email/password
authRouter.post('/register', async (c: any) => {
  try {
    const body = await c.req.json();
    const validated = RegisterSchema.parse(body);

    const db = c.env.DB;
    if (!db) return c.json({ error: 'Database not configured' }, 501);

    // Check if email already exists
    const existing = await db.prepare(
      'SELECT id FROM users WHERE email = ?'
    ).bind(validated.email.toLowerCase()).first();

    if (existing) {
      return c.json({ error: 'Email already registered' }, 409);
    }

    // Check if username is taken
    const existingUsername = await db.prepare(
      'SELECT id FROM users WHERE username = ?'
    ).bind(validated.username).first();

    if (existingUsername) {
      return c.json({ error: 'Username already taken' }, 409);
    }

    // Hash password
    const { hash, salt } = await hashPassword(validated.password);
    const userId = crypto.randomUUID();
    const verificationToken = generateVerificationToken();
    const now = new Date().toISOString().replace('T', ' ').replace('Z', '');

    // Create user (email_verified = false)
    await db.prepare(`
      INSERT INTO users (id, username, email, password_hash, password_salt, email_verified, email_verification_token, role, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, 0, ?, 'user', ?, ?)
    `).bind(userId, validated.username, validated.email.toLowerCase(), hash, salt, verificationToken, now, now).run();

    // TODO: Send verification email via email queue
    // For now, return the token for testing (remove in production!)
    const verifyUrl = `https://api.xaostech.io/auth/verify-email?token=${verificationToken}`;

    return c.json({
      message: 'Account created. Please verify your email.',
      userId,
      // Remove in production - only for testing:
      _debug_verify_url: verifyUrl,
    }, 201);
  } catch (err: any) {
    if (err.name === 'ZodError') {
      return c.json({ error: 'Validation failed', details: err.errors }, 400);
    }
    console.error('Registration error:', err);
    return c.json({ error: 'Registration failed' }, 500);
  }
});

// GET /verify-email - Verify email address
authRouter.get('/verify-email', async (c: any) => {
  const token = c.req.query('token');
  if (!token) return c.json({ error: 'Token required' }, 400);

  const db = c.env.DB;
  if (!db) return c.json({ error: 'Database not configured' }, 501);

  try {
    // Find user by verification token
    const user = await db.prepare(
      'SELECT id, email_verified FROM users WHERE email_verification_token = ?'
    ).bind(token).first() as { id: string; email_verified: number } | null;

    if (!user) {
      return c.json({ error: 'Invalid or expired token' }, 400);
    }

    if (user.email_verified) {
      return c.redirect('https://account.xaostech.io/?verified=already');
    }

    // Mark email as verified
    await db.prepare(`
      UPDATE users SET email_verified = 1, email_verification_token = NULL, updated_at = datetime('now')
      WHERE id = ?
    `).bind(user.id).run();

    return c.redirect('https://account.xaostech.io/?verified=success');
  } catch (err: any) {
    console.error('Email verification error:', err);
    return c.json({ error: 'Verification failed' }, 500);
  }
});

// POST /login - Login with email/password
authRouter.post('/login', async (c: any) => {
  try {
    const body = await c.req.json();
    const validated = LoginSchema.parse(body);

    const db = c.env.DB;
    const sessionKv = c.env.SESSIONS_KV;
    if (!db) return c.json({ error: 'Database not configured' }, 501);
    if (!sessionKv) return c.json({ error: 'Session storage not configured' }, 501);

    // Find user by email
    const user = await db.prepare(
      'SELECT id, username, email, password_hash, password_salt, email_verified, role, avatar_url FROM users WHERE email = ?'
    ).bind(validated.email.toLowerCase()).first() as {
      id: string;
      username: string;
      email: string;
      password_hash: string;
      password_salt: string;
      email_verified: number;
      role: string;
      avatar_url: string | null;
    } | null;

    if (!user) {
      return c.json({ error: 'Invalid email or password' }, 401);
    }

    // Users registered via GitHub don't have a password
    if (!user.password_hash || !user.password_salt) {
      return c.json({ error: 'This account uses GitHub login. Please sign in with GitHub.' }, 400);
    }

    // Verify password
    const validPassword = await verifyPassword(validated.password, user.password_hash, user.password_salt);
    if (!validPassword) {
      return c.json({ error: 'Invalid email or password' }, 401);
    }

    // Check email verification
    if (!user.email_verified) {
      return c.json({ error: 'Please verify your email address before logging in' }, 403);
    }

    // Create session
    const sessionId = crypto.randomUUID();
    const sessionTtl = parseInt(c.env.SESSION_TTL || '604800', 10); // 7 days
    const expires = Date.now() + sessionTtl * 1000;

    const sessionData = {
      id: user.id,
      userId: user.id,
      username: user.username,
      email: user.email,
      avatar_url: user.avatar_url,
      role: user.role || 'user',
      expires,
    };

    await sessionKv.put(sessionId, JSON.stringify(sessionData), { expirationTtl: sessionTtl });

    // Update last login
    await db.prepare(
      'UPDATE users SET last_login = datetime("now") WHERE id = ?'
    ).bind(user.id).run();

    // Set session cookie
    const cookieDomain = c.env.COOKIE_DOMAIN || '.xaostech.io';
    const sessionCookie = `session_id=${sessionId}; Domain=${cookieDomain}; Path=/; Max-Age=${sessionTtl}; HttpOnly; Secure; SameSite=Lax`;

    return new Response(JSON.stringify({
      message: 'Login successful',
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
      }
    }), {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        'Set-Cookie': sessionCookie,
      }
    });
  } catch (err: any) {
    if (err.name === 'ZodError') {
      return c.json({ error: 'Validation failed', details: err.errors }, 400);
    }
    console.error('Login error:', err);
    return c.json({ error: 'Login failed' }, 500);
  }
});

// POST /forgot-password - Request password reset
authRouter.post('/forgot-password', async (c: any) => {
  try {
    const { email } = await c.req.json();
    if (!email) return c.json({ error: 'Email required' }, 400);

    const db = c.env.DB;
    if (!db) return c.json({ error: 'Database not configured' }, 501);

    // Find user
    const user = await db.prepare(
      'SELECT id, password_hash FROM users WHERE email = ?'
    ).bind(email.toLowerCase()).first() as { id: string; password_hash: string | null } | null;

    // Always return success to prevent email enumeration
    if (!user || !user.password_hash) {
      return c.json({ message: 'If an account exists, a password reset link will be sent.' });
    }

    // Generate reset token
    const resetToken = generateVerificationToken();
    const resetExpires = new Date(Date.now() + 3600000).toISOString().replace('T', ' ').replace('Z', ''); // 1 hour

    await db.prepare(`
      UPDATE users SET password_reset_token = ?, password_reset_expires = ? WHERE id = ?
    `).bind(resetToken, resetExpires, user.id).run();

    // TODO: Send reset email via email queue
    const resetUrl = `https://account.xaostech.io/reset-password?token=${resetToken}`;

    return c.json({
      message: 'If an account exists, a password reset link will be sent.',
      // Remove in production:
      _debug_reset_url: resetUrl,
    });
  } catch (err: any) {
    console.error('Forgot password error:', err);
    return c.json({ error: 'Request failed' }, 500);
  }
});

// POST /reset-password - Reset password with token
authRouter.post('/reset-password', async (c: any) => {
  try {
    const { token, password } = await c.req.json();
    if (!token || !password) return c.json({ error: 'Token and password required' }, 400);

    // Validate password strength
    if (password.length < 8 || !/[A-Z]/.test(password) || !/[0-9]/.test(password)) {
      return c.json({ error: 'Password must be 8+ characters with uppercase and number' }, 400);
    }

    const db = c.env.DB;
    if (!db) return c.json({ error: 'Database not configured' }, 501);

    // Find user by reset token
    const user = await db.prepare(
      'SELECT id, password_reset_expires FROM users WHERE password_reset_token = ?'
    ).bind(token).first() as { id: string; password_reset_expires: string } | null;

    if (!user) {
      return c.json({ error: 'Invalid or expired reset token' }, 400);
    }

    // Check expiration
    const expires = new Date(user.password_reset_expires.replace(' ', 'T') + 'Z');
    if (expires < new Date()) {
      return c.json({ error: 'Reset token has expired' }, 400);
    }

    // Hash new password
    const { hash, salt } = await hashPassword(password);

    // Update password and clear reset token
    await db.prepare(`
      UPDATE users SET password_hash = ?, password_salt = ?, password_reset_token = NULL, password_reset_expires = NULL, updated_at = datetime('now')
      WHERE id = ?
    `).bind(hash, salt, user.id).run();

    return c.json({ message: 'Password reset successfully. You can now log in.' });
  } catch (err: any) {
    console.error('Reset password error:', err);
    return c.json({ error: 'Reset failed' }, 500);
  }
});
