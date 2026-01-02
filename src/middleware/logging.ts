import { Context, Next } from 'hono';

export interface LogEntry {
  timestamp: string;
  method: string;
  path: string;
  status: number;
  duration: number;
  userId?: string;
  ip?: string;
  userAgent?: string;
  error?: string;
}

/**
 * Logging Middleware - Local to each worker
 * 
 * Records request/response metadata:
 * - Method, path, status code, duration
 * - User ID if authenticated
 * - IP address, user agent
 * - Errors if they occur
 * 
 * Can integrate with:
 * - KV storage for archival
 * - Console for CloudFlare logs
 * - D1 database for analytics
 * 
 * Best practice: Keep each service's logs self-contained
 * api.xaostech.io logs its own requests
 * chat.xaostech.io logs its own requests, etc.
 */
export async function loggingMiddleware(c: Context, next: Next) {
  const startTime = Date.now();
  const request = c.req;

  // Extract request metadata
  const logEntry: LogEntry = {
    timestamp: new Date().toISOString(),
    method: request.method,
    path: request.path,
    status: 200, // Will be updated after handler
    duration: 0,
    ip: request.header('cf-connecting-ip') || request.header('x-forwarded-for') || 'unknown',
    userAgent: request.header('user-agent'),
  };

  // Attach userId if authenticated
  try {
    const auth = c.get('auth');
    if (auth?.userId) {
      logEntry.userId = auth.userId;
    }
  } catch {
    // Auth not set yet, skip
  }

  // Call next handler
  await next();

  // Capture response status and duration
  logEntry.status = c.res.status;
  logEntry.duration = Date.now() - startTime;

  // Send to local logging (console, KV, or D1)
  await recordLog(c, logEntry);

  // Attach log info to response header for debugging
  c.res.headers.set('X-Request-Duration', `${logEntry.duration}ms`);
}

/**
 * Record log entry to storage
 * Multiple storage options:
 */
async function recordLog(c: Context, log: LogEntry) {
  // Option 1: Console (always available, visible in CloudFlare dashboard)
  console.log(`[${log.method}] ${log.path} → ${log.status} (${log.duration}ms)${log.userId ? ` [${log.userId}]` : ''}`);

  // Option 2: KV Storage (if LOG_KV binding exists)
  try {
    const logKv = c.env?.LOG_KV;
    if (logKv) {
      // Store with timestamp key for easy retrieval
      const key = `log:${Date.now()}:${Math.random().toString(36).substr(2, 9)}`;
      await logKv.put(key, JSON.stringify(log), { expirationTtl: 2592000 }); // 30 days
    }
  } catch (err) {
    console.error('Failed to write to LOG_KV:', err);
  }

  // Option 3: D1 Database (if you add a logs table)
  try {
    const db = c.env?.DB;
    if (db && log.status >= 400) {
      // Log errors to database for tracking
      await db.prepare(
        'INSERT INTO request_logs (timestamp, method, path, status, duration, user_id, ip, error) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
      ).bind(
        log.timestamp,
        log.method,
        log.path,
        log.status,
        log.duration,
        log.userId || null,
        log.ip,
        log.error || null
      ).run();
    }
  } catch (err) {
    console.error('Failed to write to DB logs:', err);
  }
}

/**
 * Format log for human readability
 */
export function formatLog(log: LogEntry): string {
  return [
    `[${log.timestamp}]`,
    `${log.method.padEnd(6)} ${log.path}`,
    `→ ${log.status}`,
    `${log.duration}ms`,
    log.userId ? `[${log.userId}]` : '',
    log.error ? `ERROR: ${log.error}` : '',
  ].filter(Boolean).join(' ');
}
