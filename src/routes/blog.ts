import { Hono } from 'hono';
import { requireAuth } from '../middleware/auth';

export const blogRouter = new Hono();

// List posts - proxy to DATA worker
blogRouter.get('/posts', async (c: any) => {
  const dataService = c.env.DATA;
  if (!dataService) return c.json({ error: 'DATA service not configured' }, 501);

  try {
    const resp = await dataService.fetch('https://data.xaostech.io/blog/posts');
    return resp;
  } catch (err) {
    return c.json({ error: 'Failed to fetch posts' }, 500);
  }
});

// Read post - proxy to DATA worker
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
  const { title, content, slug, published } = body;
  if (!title || !content) return c.json({ error: 'title and content required' }, 400);

  try {
    const resp = await dataService.fetch('https://data.xaostech.io/blog/posts', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        title,
        content,
        slug,
        author_id: auth.userId,
        status: published ? 'published' : 'draft',
      }),
    });
    return resp;
  } catch (err) {
    console.error('Create post error', err);
    return c.json({ error: 'Failed to create post' }, 500);
  }
});
