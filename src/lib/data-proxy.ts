export function getDataAccessCredentials(c: any) {
  return {
    id: c.env?.DATA_ACCESS_CLIENT_ID,
    secret: c.env?.DATA_ACCESS_CLIENT_SECRET,
  };
}

export function getDataFetchHeaders(c: any, extra: Record<string, string> = {}) {
  const headers: Record<string, string> = {
    'User-Agent': 'XAOSTECH API Worker',
    'X-Proxy-Source': 'api.xaostech.io',
    ...extra,
  };

  const incomingTrace = (c.req && (c.req.header?.('X-Trace-Id') || c.req.header('X-Trace-Id'))) || undefined;
  if (incomingTrace) headers['X-Trace-Id'] = incomingTrace;

  const { id, secret } = getDataAccessCredentials(c);
  if (id && secret) {
    headers['CF-Access-Client-Id'] = id;
    headers['CF-Access-Client-Secret'] = secret;
  }

  const safeLog = {
    traceId: headers['X-Trace-Id'] || null,
    hasCfAccessId: !!headers['CF-Access-Client-Id'],
    hasCfAccessSecret: !!headers['CF-Access-Client-Secret'],
    extras: Object.keys(extra || {}),
  };
  console.debug('[data-proxy] getDataFetchHeaders presence:', safeLog);

  return headers;
}

export function ensureDataAccessOrReject(c: any) {
  const { id, secret } = getDataAccessCredentials(c);
  if (!id || !secret) {
    console.error('[data-proxy] Missing DATA_ACCESS service credentials; rejecting request');
    return c.json({ error: 'Missing DATA service token' }, 502);
  }
  return null;
}

/**
 * Centralized fetch wrapper for requests to data.xaostech.io
 * - Uses Service Binding when available (worker-to-worker, bypasses public internet)
 * - Falls back to HTTP fetch if binding not available
 * - Returns the underlying Response
 */
export async function fetchData(c: any, path: string, opts: RequestInit = {}, extraHeaders: Record<string,string> = {}) {
  const defaultHeaders = getDataFetchHeaders(c, extraHeaders);
  const headers = new Headers(defaultHeaders);
  // Merge any provided headers
  if (opts.headers) {
    const inHeaders = opts.headers instanceof Headers ? opts.headers : new Headers(opts.headers as any);
    inHeaders.forEach((v, k) => headers.set(k, v));
  }

  const requestInit: RequestInit = { ...opts, headers };
  const traceId = (c.req && (c.req.header?.('X-Trace-Id') || c.req.header('X-Trace-Id'))) || null;

  // Prefer Service Binding (DATA) - direct worker-to-worker, no public internet
  const dataBinding = c.env?.DATA;
  if (dataBinding) {
    const url = new URL(path, 'https://data.xaostech.io');
    console.debug('[data-proxy] fetchData via Service Binding', { path: url.pathname, method: requestInit.method || 'GET', traceId });

    let res: Response;
    try {
      res = await dataBinding.fetch(new Request(url.toString(), requestInit));
    } catch (err: any) {
      console.error('[data-proxy] Service Binding fetch error', { path: url.pathname, traceId, err: err?.message || String(err) });
      throw err;
    }

    const contentType = res.headers.get('content-type') || '';
    console.debug('[data-proxy] Service Binding response', { path: url.pathname, status: res.status, contentType, traceId });

    if (!res.ok) {
      let upstreamBody = '';
      try { const t = await res.clone().text(); upstreamBody = t ? (t.length > 512 ? t.slice(0,512)+'...' : t) : ''; } catch (e) { upstreamBody = '[failed to read upstream body]'; }
      console.error('[data-proxy] Service Binding upstream non-ok', { path: url.pathname, status: res.status, traceId, upstreamSnippet: upstreamBody.slice(0,256) });
    }

    return res;
  }

  // Fallback: HTTP fetch (goes through public internet, requires Access headers if protected)
  const baseUrl = 'https://data.xaostech.io';
  const url = path.startsWith('http') ? path : `${baseUrl}${path}`;

  const { id, secret } = getDataAccessCredentials(c);
  console.debug('[data-proxy] fetchData via HTTP (no Service Binding)', { url, method: requestInit.method || 'GET', traceId, hasDataId: !!id, hasDataSecret: !!secret, extraKeys: Object.keys(extraHeaders || {}) });

  let res: Response;
  try {
    res = await fetch(url, requestInit);
  } catch (err: any) {
    console.error('[data-proxy] HTTP fetch network error', { url, method: requestInit.method || 'GET', traceId, err: err?.message || String(err) });
    throw err;
  }

  const contentType = res.headers.get('content-type') || '';
  console.debug('[data-proxy] HTTP fetch response', { url, status: res.status, contentType, traceId });

  // If upstream returned an HTML login page, surface that as blocked
  if (res.status === 200 && contentType.includes('text/html')) {
    const txt = await res.text();
    if (txt.includes('Cloudflare') || txt.includes('Sign in') || txt.includes('Access')) {
      const snippet = txt ? (txt.length > 512 ? txt.slice(0, 512) + '...' : txt) : '';
      console.error('[data-proxy] HTTP fetch blocked by Cloudflare Access', { url, traceId, snippet: snippet.slice(0,256) });
      return new Response(JSON.stringify({ error: 'Blocked by Cloudflare Access' }), { status: 502, headers: { 'Content-Type': 'application/json' } });
    }
  }

  if (!res.ok) {
    let upstreamBody = '';
    try { const t = await res.clone().text(); upstreamBody = t ? (t.length > 512 ? t.slice(0,512)+'...' : t) : ''; } catch (e) { upstreamBody = '[failed to read upstream body]'; }
    console.error('[data-proxy] HTTP fetch upstream non-ok', { url, status: res.status, traceId, upstreamSnippet: upstreamBody.slice(0,256) });
  }

  return res;
}