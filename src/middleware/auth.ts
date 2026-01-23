import { Context, Next } from 'hono';

export interface AuthContext {
  userId?: string;
  sessionId?: string;
  isAdmin?: boolean;
  scope?: string[];
  error?: string;
  // API key specific fields
  isApiKey?: boolean;
  keyId?: string;
  keyName?: string;
  rateLimit?: number;
}

/**
 * Auth Middleware - Verifies token via account.xaostech.io
 * 
 * Validates incoming requests against account service:
 * - Checks X-API-Key header (user-generated API keys for CLI/programmatic access)
 * - Checks Authorization header (Bearer token or Session ID)
 * - Checks session_id cookie
 * - Calls account.xaostech.io/verify or /verify-api-key to validate
 * - Sets context with user info if valid
 * 
 * Public routes: Skip auth or allow guest access
 * Admin routes: Require isAdmin=true
 * Protected routes: Require valid session or API key
 */
export async function authMiddleware(c: Context, next: Next) {
  const pathname = c.req.path;
  
  // Public endpoints - skip auth
  // Assets are public, don't require authentication
  if (pathname.startsWith('/data/assets/')) {
    return next();
  }
  
  // Check for API key first (X-API-Key header)
  const apiKey = c.req.header('X-API-Key');
  
  const authHeader = c.req.header('Authorization');
  // getCookie is the correct Hono method for reading cookies
  const cookieSession = c.req.query('session_id') || c.req.header('Cookie')?.split('session_id=')[1]?.split(';')[0];

  const auth: AuthContext = {
    userId: undefined,
    sessionId: undefined,
    isAdmin: false,
    scope: [],
    error: 'no_auth',
    isApiKey: false,
  };

  // Priority 1: API Key authentication (for CLI/programmatic access)
  if (apiKey && apiKey.startsWith('xk_')) {
    try {
      const verifyResponse = await fetch('https://account.xaostech.io/verify-api-key', {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          // Forward client IP for IP allowlist checking
          'CF-Connecting-IP': c.req.header('CF-Connecting-IP') || '',
          'X-Real-IP': c.req.header('X-Real-IP') || '',
        },
        body: JSON.stringify({ apiKey }),
      });

      if (verifyResponse.ok) {
        const keyData = await verifyResponse.json() as any;
        auth.userId = keyData.userId;
        auth.isAdmin = keyData.isAdmin || false;
        auth.scope = keyData.scopes || [];
        auth.error = undefined;
        auth.isApiKey = true;
        auth.keyId = keyData.keyId;
        auth.keyName = keyData.keyName;
        auth.rateLimit = keyData.rateLimit;
      } else {
        const errData = await verifyResponse.json().catch(() => ({})) as any;
        auth.error = errData.error || 'invalid_api_key';
      }
    } catch (err) {
      console.error('API key verification failed:', err);
      auth.error = 'auth_service_error';
    }
  } 
  // Priority 2: Bearer token or session cookie
  else {
    let token = '';
    let tokenType = 'bearer'; // 'bearer' or 'session'

    if (authHeader?.startsWith('Bearer ')) {
      token = authHeader.slice(7);
      tokenType = 'bearer';
    } else if (cookieSession) {
      token = cookieSession;
      tokenType = 'session';
    }

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
          const userData = await verifyResponse.json() as any;
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
