import test from 'node:test';
import assert from 'node:assert/strict';
import worker from '../src/index.js';

test('Worker responds with 200 on health check GET /', async () => {
  const req = new Request('http://localhost/', { method: 'GET' });
  const res = await worker.fetch(req, {}, {});
  assert.equal(res.status, 200);
  const text = await res.text();
  assert.equal(text, '2FAuth Worker is running.');
});

test('Worker returns 404 on unknown routes', async () => {
  const req = new Request('http://localhost/unknown', { method: 'GET' });
  const res = await worker.fetch(req, {}, {});
  assert.equal(res.status, 404);
});
