const crypto = require('crypto');
const express = require('express');
const { dispatch } = require('./dispatcher');
const config = require('./config');
const { validateWebhookUrl } = require('./urlPolicy');

if (!config.API_KEY) {
  // Fail closed: never run this service unauthenticated.
  throw new Error('NOTIFY_API_KEY (or NOTIFY_API_KEY_FILE) must be set');
}

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '64kb' }));

// Health is the only unauthenticated route (used by probes).
app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'vulntracker-notify' });
});

// Bearer-token authentication for everything else (constant-time compare).
const expectedKeyDigest = crypto.createHash('sha256').update(config.API_KEY).digest();
app.use((req, res, next) => {
  const header = req.get('authorization') || '';
  const supplied = header.startsWith('Bearer ') ? header.slice(7) : '';
  const suppliedDigest = crypto.createHash('sha256').update(supplied).digest();
  if (!supplied || !crypto.timingSafeEqual(suppliedDigest, expectedKeyDigest)) {
    return res.status(401).json({ error: 'unauthorized' });
  }
  next();
});

// In-memory webhook registry
const webhooks = new Map();
const ALLOWED_EVENTS = new Set(['scan.created', 'scan.updated']);

// Copy only plain string/number/boolean values into a prototype-less object
// (blocks __proto__ / constructor pollution and unbounded blobs).
function sanitiseMetadata(metadata) {
  const out = Object.create(null);
  if (!metadata || typeof metadata !== 'object' || Array.isArray(metadata)) return out;
  for (const [k, v] of Object.entries(metadata).slice(0, 20)) {
    if (k === '__proto__' || k === 'constructor' || k === 'prototype') continue;
    if (['string', 'number', 'boolean'].includes(typeof v)) out[k] = typeof v === 'string' ? v.slice(0, 256) : v;
  }
  return { ...out };
}


// Register a webhook endpoint to receive VulnTracker events
app.post('/webhooks', (req, res) => {
  const { url, events, metadata } = req.body || {};

  if (!url || typeof url !== 'string') return res.status(400).json({ error: 'url is required' });
  if (!Array.isArray(events) || events.length === 0) {
    return res.status(400).json({ error: 'events must be a non-empty array' });
  }
  if (!events.every(e => ALLOWED_EVENTS.has(e))) {
    return res.status(400).json({ error: 'unknown event type' });
  }
  const urlError = validateWebhookUrl(url, { allowInsecure: config.ALLOW_INSECURE_WEBHOOKS });
  if (urlError) return res.status(400).json({ error: urlError });

  const webhook = {
    id: crypto.randomUUID(),
    url,
    events,
    metadata: sanitiseMetadata(metadata),
    createdAt: new Date().toISOString(),
  };

  webhooks.set(webhook.id, webhook);
  res.status(201).json(webhook);
});


// List all registered webhooks
app.get('/webhooks', (req, res) => {
  res.json({ webhooks: Array.from(webhooks.values()), count: webhooks.size });
});


// Delete a webhook registration
app.delete('/webhooks/:id', (req, res) => {
  if (!webhooks.has(req.params.id)) {
    return res.status(404).json({ error: 'Webhook not found' });
  }
  webhooks.delete(req.params.id);
  res.status(204).send();
});


// Trigger event notifications — called by the Python API on scan create/update
// Authenticated (bearer key) and additionally restricted by NetworkPolicy in Kubernetes
app.post('/notify', async (req, res) => {
  const { event, payload } = req.body || {};

  if (!event || !payload) {
    return res.status(400).json({ error: 'event and payload are required' });
  }

  const matching = Array.from(webhooks.values()).filter(w => w.events.includes(event));

  const results = await Promise.all(
    matching.map(w => dispatch(w, { event, payload, timestamp: new Date().toISOString() }))
  );

  res.json({ event, dispatched: matching.length, results });
});


// Global error handler - details stay in server logs, never in responses.
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  const errorId = crypto.randomUUID();
  console.error(`error_id=${errorId}`, err);
  const status = err.status && err.status < 500 ? err.status : 500;
  res.status(status).json({ error: status === 500 ? 'Internal server error' : 'Bad request', error_id: errorId });
});


if (require.main === module) {
  app.listen(config.PORT, () => {
    console.log(`Notification service running on http://localhost:${config.PORT}`);
  });
}

module.exports = app;
