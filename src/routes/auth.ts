import { Hono } from 'hono';

export const authRouter = new Hono();

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

// GitHub OAuth
authRouter.get('/github/login', (c: any) => {
  const clientId = c.env.GITHUB_OAUTH_CLIENT_ID;
  if (!clientId) return c.json({ error: 'GITHUB_OAUTH_CLIENT_ID not configured' }, 501);

  // Support return_to parameter for post-login redirect
  const returnTo = c.req.query('return_to') || 'https://account.xaostech.io';
  const safeReturnTo = isValidReturnTo(returnTo) ? returnTo : 'https://account.xaostech.io';

  const state = crypto.randomUUID();
  // Build redirect_uri from the request URL (will be account.xaostech.io/api/auth/github/callback when proxied)
  const redirectUri = new URL('/auth/github/callback', c.req.url).toString();

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

  try {
    const tokenResp = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: { 'Accept': 'application/json', 'Content-Type': 'application/json' },
      body: JSON.stringify({ client_id: clientId, client_secret: clientSecret, code }),
    });
    const tokenJson = await tokenResp.json();
    const accessToken = tokenJson.access_token;
    if (!accessToken) return c.json({ error: 'Failed to obtain access token' }, 502);

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

    const db = c.env.DB;
    if (!db) return c.json({ error: 'DB not configured on api.xaostech.io' }, 501);

    const existingRow = await db.prepare('SELECT id FROM users WHERE github_id = ?').bind(ghUser.id.toString()).first();
    const existing = existingRow as { id?: string } | undefined;
    let userId = existing?.id;
    if (userId) {
      await db.prepare('UPDATE users SET username = ?, email = ?, avatar_url = ?, last_login = datetime("now") WHERE id = ?')
        .bind(ghUser.login || '', primaryEmail || '', ghUser.avatar_url || '', userId).run();
    } else {
      userId = crypto.randomUUID();
      await db.prepare('INSERT INTO users (id, github_id, username, email, avatar_url, created_at, last_login) VALUES (?, ?, ?, ?, ?, datetime("now"), datetime("now"))')
        .bind(userId, ghUser.id.toString(), ghUser.login || '', primaryEmail || '', ghUser.avatar_url || '').run();
    }

    const sessionKv = c.env.SESSION;
    if (!sessionKv) return c.json({ error: 'SESSION KV not configured' }, 501);

    const sessionId = crypto.randomUUID();
    const sessionTtl = 60 * 60 * 24 * 7; // 7 days
    // Store full user data in session for cross-worker access
    const sessionData = {
      userId,
      username: ghUser.login || '',
      email: primaryEmail || '',
      avatar_url: ghUser.avatar_url || '',
      github_id: ghUser.id.toString(),
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
    return c.json({ error: 'GitHub OAuth failed' }, 500);
  }
});

authRouter.post('/logout', async (c: any) => {
  try {
    const sessionKv = c.env.SESSION;
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
    const sessionKv = c.env.SESSION;
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
