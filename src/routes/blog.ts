import { Hono } from 'hono';
import { requireAuth } from '../middleware/auth';

export const blogRouter = new Hono();

// List posts - proxy to DATA worker
blogRouter.get('/posts', async (c: any) => {
  const dataService = c.env.DATA;
  if (!dataService) return c.json({ error: 'DATA service not configured' }, 501);

  const limit = c.req.query('limit') || '50';
  const offset = c.req.query('offset') || '0';

  try {
    const resp = await dataService.fetch(`https://data.xaostech.io/blog/posts?limit=${limit}&offset=${offset}`);
    return resp;
  } catch (err) {
    return c.json({ error: 'Failed to fetch posts' }, 500);
  }
});

// Read post by slug or id - proxy to DATA worker
blogRouter.get('/posts/:id', async (c: any) => {
  const id = c.req.param('id');
  const dataService = c.env.DATA;
  if (!dataService) return c.json({ error: 'DATA service not configured' }, 501);

  try {
    const resp = await dataService.fetch(`https://data.xaostech.io/blog/posts/${id}`);
    return resp;
  } catch (err) {
    return c.json({ error: 'Failed to fetch post' }, 500);
  }
});

// Create post (requires auth) - proxy to DATA worker
blogRouter.post('/posts', requireAuth, async (c: any) => {
  const auth = c.get('auth') as any;
  const dataService = c.env.DATA;
  if (!dataService) return c.json({ error: 'DATA service not configured' }, 501);

  const body = await c.req.json().catch(() => ({}));
  const { title, content, slug, excerpt, featured_image_url, status } = body;
  if (!title || !content) return c.json({ error: 'title and content required' }, 400);

  try {
    const resp = await dataService.fetch('https://data.xaostech.io/blog/posts', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        title,
        content,
        slug,
        excerpt,
        featured_image_url,
        author_id: auth.userId,
        status: status || 'draft',
      }),
    });
    return resp;
  } catch (err) {
    console.error('Create post error', err);
    return c.json({ error: 'Failed to create post' }, 500);
  }
});

// Update post (requires auth) - proxy to DATA worker
blogRouter.put('/posts/:id', requireAuth, async (c: any) => {
  const id = c.req.param('id');
  const auth = c.get('auth') as any;
  const dataService = c.env.DATA;
  if (!dataService) return c.json({ error: 'DATA service not configured' }, 501);

  const body = await c.req.json().catch(() => ({}));

  try {
    const resp = await dataService.fetch(`https://data.xaostech.io/blog/posts/${id}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'X-User-Id': auth.userId,
      },
      body: JSON.stringify(body),
    });
    return resp;
  } catch (err) {
    console.error('Update post error', err);
    return c.json({ error: 'Failed to update post' }, 500);
  }
});

// Delete post (requires auth) - proxy to DATA worker
blogRouter.delete('/posts/:id', requireAuth, async (c: any) => {
  const id = c.req.param('id');
  const auth = c.get('auth') as any;
  const dataService = c.env.DATA;
  if (!dataService) return c.json({ error: 'DATA service not configured' }, 501);

  try {
    const resp = await dataService.fetch(`https://data.xaostech.io/blog/posts/${id}`, {
      method: 'DELETE',
      headers: {
        'X-User-Id': auth.userId,
      },
    });
    return resp;
  } catch (err) {
    console.error('Delete post error', err);
    return c.json({ error: 'Failed to delete post' }, 500);
  }
});
