import { Context, Next } from 'hono';

export interface AuthContext {
  userId?: string;
  sessionId?: string;
  isAdmin?: boolean;
  scope?: string[];
  error?: string;
}

/**
 * Auth Middleware - Verifies token via account.xaostech.io
 * 
 * Validates incoming requests against account service:
 * - Checks Authorization header (Bearer token or Session ID)
 * - Calls account.xaostech.io/verify to validate
 * - Sets context with user info if valid
 * 
 * Public routes: Skip auth or allow guest access
 * Admin routes: Require isAdmin=true
 * Protected routes: Require valid session
 */
export async function authMiddleware(c: Context, next: Next) {
  const pathname = c.req.path;
  
  // Public endpoints - skip auth
  // Assets are public, don't require authentication
  if (pathname.startsWith('/data/assets/')) {
    return next();
  }
  
  const authHeader = c.req.header('Authorization');
  // getCookie is the correct Hono method for reading cookies
  const cookieSession = c.req.query('session_id') || c.req.header('Cookie')?.split('session_id=')[1]?.split(';')[0];

  let token = '';
  let tokenType = 'bearer'; // 'bearer' or 'session'

  if (authHeader?.startsWith('Bearer ')) {
    token = authHeader.slice(7);
    tokenType = 'bearer';
  } else if (cookieSession) {
    token = cookieSession;
    tokenType = 'session';
  }

  const auth: AuthContext = {
    userId: undefined,
    sessionId: undefined,
    isAdmin: false,
    scope: [],
    error: token ? undefined : 'no_auth', // Only error if auth is required later
  };

  // If token exists, verify with account service
  if (token) {
    try {
      const verifyResponse = await fetch('https://account.xaostech.io/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          token,
          tokenType,
        }),
      });

      if (verifyResponse.ok) {
        const userData = await verifyResponse.json();
        auth.userId = userData.userId;
        auth.sessionId = userData.sessionId;
        auth.isAdmin = userData.isAdmin || false;
        auth.scope = userData.scope || [];
        auth.error = undefined;
      } else {
        auth.error = 'invalid_token';
      }
    } catch (err) {
      console.error('Auth verification failed:', err);
      auth.error = 'auth_service_error';
    }
  }

  // Store in context for use in handlers
  c.set('auth', auth);

  await next();
}

/**
 * Require Auth Middleware
 * Throws 401 if not authenticated
 */
export async function requireAuth(c: Context, next: Next) {
  const auth = c.get('auth') as AuthContext;

  if (!auth.userId) {
    return c.json(
      { error: 'Unauthorized', reason: auth.error || 'no_auth' },
      401
    );
  }

  await next();
}

/**
 * Require Admin Middleware
 * Throws 403 if user is not admin
 */
export async function requireAdmin(c: Context, next: Next) {
  const auth = c.get('auth') as AuthContext;

  if (!auth.isAdmin) {
    return c.json(
      { error: 'Forbidden', reason: 'admin_required' },
      403
    );
  }

  await next();
}

/**
 * Require Scope Middleware
 * Verifies user has specific API scope
 */
export function requireScope(requiredScope: string) {
  return async (c: Context, next: Next) => {
    const auth = c.get('auth') as AuthContext;

    if (!auth.scope?.includes(requiredScope)) {
      return c.json(
        { error: 'Forbidden', reason: 'insufficient_scope', required: requiredScope },
        403
      );
    }

    await next();
  };
}

/**
 * Get current user from context
 */
export function getAuth(c: Context): AuthContext {
  return c.get('auth') as AuthContext;
}
