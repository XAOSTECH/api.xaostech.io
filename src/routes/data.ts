import { Hono } from 'hono';
import { getSecurityHeaders } from '../../shared/types/security';
import { ensureDataAccessOrReject, getDataFetchHeaders, fetchData } from '../lib/data-proxy';

export const dataRouter = new Hono();

// Asset handler (exported so index.ts can mount it directly)
export async function handleAsset(c: any) {
  const filename = c.req.param('filename');
  if (!filename) return c.json({ error: 'Filename required' }, 400);

  const traceId = c.req.header('X-Trace-Id') || null;
  console.debug('[DATA] handleAsset request', { filename, path: c.req.path, traceId });

  try {
    const maybeReject = ensureDataAccessOrReject(c);
    if (maybeReject) return maybeReject;

    const fetchHeadersObj = getDataFetchHeaders(c);
    const safeLogAssets = {
      hasProxySource: !!fetchHeadersObj['X-Proxy-Source'],
      hasCfAccessId: !!fetchHeadersObj['CF-Access-Client-Id'],
      hasCfAccessSecret: !!fetchHeadersObj['CF-Access-Client-Secret']
    };
    console.debug('[DATA] Outgoing header presence for assets fetch:', safeLogAssets);

    const response = await fetchData(c, `/assets/${filename}`, { method: 'GET' });

    console.debug('[DATA] handleAsset -> fetch result', { filename, status: response.status, traceId });

    if (!response.ok) {
      const traceAsset = c.req.header('X-Trace-Id') || null;
      console.error('[ASSET] Upstream returned non-ok for asset fetch', { status: response.status, traceId: traceAsset });
      return c.json({ error: 'Asset not found' }, response.status);
    }

    const blob = await response.blob();
    const headers = new Headers(response.headers);
    headers.set('Cache-Control', 'public, max-age=604800');

    const sec = getSecurityHeaders();
    for (const k in sec) headers.set(k, sec[k]);

    console.log(`[ASSET] Returning ${filename} (${blob.size} bytes)`);

    return new Response(blob, { status: 200, headers });
  } catch (err: any) {
    console.error('[ASSET] Fetch error:', err.message, err.stack);
    return c.json({ error: 'Failed to fetch asset' }, 500);
  }
}

// Mount on router too
dataRouter.get('/assets/:filename', handleAsset);
