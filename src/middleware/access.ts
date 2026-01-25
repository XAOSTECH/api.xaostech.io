/**
 * =============================================================================
 * Cloudflare Access JWT Validation Middleware
 * =============================================================================
 * Validates the Cf-Access-Jwt-Assertion header from Cloudflare Access
 * 
 * When behind an Access policy, CF adds this JWT to all requests.
 * Validating it ensures the request came through Access, not directly.
 * 
 * Required env vars:
 * - CF_ACCESS_TEAM_DOMAIN: https://<team>.cloudflareaccess.com
 * - CF_ACCESS_AUD: Application Audience (AUD) tag from Access dashboard
 * =============================================================================
 */

import { Context, Next } from 'hono';
import { jwtVerify, createRemoteJWKSet, JWTPayload } from 'jose';

export interface AccessJWTPayload extends JWTPayload {
    email?: string;
    identity_nonce?: string;
    sub?: string;
    iss?: string;
    aud?: string[];
    exp?: number;
    iat?: number;
    type?: string;
    country?: string;
}

export interface AccessContext {
    valid: boolean;
    email?: string;
    sub?: string;
    country?: string;
    error?: string;
}

// Cache the JWKS for performance (it's fetched remotely)
let cachedJWKS: ReturnType<typeof createRemoteJWKSet> | null = null;
let jwksCacheTime = 0;
const JWKS_CACHE_TTL = 300000; // 5 minutes

function getJWKS(teamDomain: string): ReturnType<typeof createRemoteJWKSet> {
    const now = Date.now();
    if (cachedJWKS && (now - jwksCacheTime) < JWKS_CACHE_TTL) {
        return cachedJWKS;
    }

    const certsUrl = new URL(`${teamDomain}/cdn-cgi/access/certs`);
    cachedJWKS = createRemoteJWKSet(certsUrl);
    jwksCacheTime = now;
    return cachedJWKS;
}

/**
 * Validate Cloudflare Access JWT
 * 
 * @param token - The JWT from Cf-Access-Jwt-Assertion header
 * @param teamDomain - Your team domain (https://<team>.cloudflareaccess.com)
 * @param audience - Application AUD tag
 */
export async function validateAccessJWT(
    token: string,
    teamDomain: string,
    audience: string
): Promise<{ valid: boolean; payload?: AccessJWTPayload; error?: string }> {
    try {
        const JWKS = getJWKS(teamDomain);

        const { payload } = await jwtVerify(token, JWKS, {
            issuer: teamDomain,
            audience: audience,
        });

        return {
            valid: true,
            payload: payload as AccessJWTPayload,
        };
    } catch (error) {
        const message = error instanceof Error ? error.message : 'Unknown error';
        console.error('[ACCESS JWT] Validation failed:', message);
        return {
            valid: false,
            error: message,
        };
    }
}

/**
 * Middleware to validate Cloudflare Access JWT
 * 
 * This validates that requests came through Cloudflare Access policy.
 * It does NOT replace user authentication - use alongside authMiddleware.
 * 
 * Set `required: true` to reject requests without valid Access JWT.
 * Set `required: false` to allow but extract info if present.
 */
export function accessJWTMiddleware(options: { required?: boolean } = {}) {
    const { required = false } = options;

    return async (c: Context, next: Next) => {
        const teamDomain = c.env?.CF_ACCESS_TEAM_DOMAIN;
        const audience = c.env?.CF_ACCESS_AUD;

        // Check if Access validation is configured
        if (!teamDomain || !audience) {
            if (required) {
                console.warn('[ACCESS JWT] Team domain or AUD not configured');
            }
            c.set('access', { valid: false, error: 'not_configured' } as AccessContext);
            return next();
        }

        // Get the JWT from header (preferred) or cookie
        const token = c.req.header('Cf-Access-Jwt-Assertion') ||
            c.req.header('Cookie')?.split('CF_Authorization=')[1]?.split(';')[0];

        if (!token) {
            if (required) {
                return c.json({
                    error: 'Access denied',
                    reason: 'Missing Cloudflare Access JWT'
                }, 403);
            }
            c.set('access', { valid: false, error: 'no_token' } as AccessContext);
            return next();
        }

        // Validate the JWT
        const result = await validateAccessJWT(token, teamDomain, audience);

        if (!result.valid) {
            if (required) {
                return c.json({
                    error: 'Access denied',
                    reason: result.error || 'Invalid Access JWT'
                }, 403);
            }
            c.set('access', { valid: false, error: result.error } as AccessContext);
            return next();
        }

        // Store Access context for handlers
        const accessContext: AccessContext = {
            valid: true,
            email: result.payload?.email,
            sub: result.payload?.sub,
            country: result.payload?.country,
        };
        c.set('access', accessContext);

        await next();
    };
}

/**
 * Get Access context from request
 */
export function getAccess(c: Context): AccessContext {
    return c.get('access') as AccessContext || { valid: false, error: 'not_set' };
}

/**
 * Require valid Access JWT
 * Use this on specific routes that MUST come through Access
 */
export async function requireAccess(c: Context, next: Next) {
    const access = getAccess(c);

    if (!access.valid) {
        return c.json({
            error: 'Access denied',
            reason: access.error || 'Valid Cloudflare Access JWT required',
        }, 403);
    }

    await next();
}
