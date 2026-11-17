const crypto = require('crypto');
const axios = require('axios');
const config = require('./config');
const { assertPublicDestination } = require('./urlPolicy');

function sign(body) {
  const secret = config.WEBHOOK_SIGNING_SECRET || config.API_KEY || '';
  return 'sha256=' + crypto.createHmac('sha256', secret).update(body).digest('hex');
}

async function dispatch(webhook, payload) {
  const body = JSON.stringify(payload);
  for (let attempt = 1; attempt <= config.RETRY_ATTEMPTS; attempt++) {
    try {
      await assertPublicDestination(webhook.url);
      await axios.post(webhook.url, body, {
        timeout: config.TIMEOUT_MS,
        maxRedirects: 0,            // redirects are a classic SSRF bypass
        maxContentLength: 64 * 1024,
        headers: {
          'Content-Type': 'application/json',
          // Receivers verify authenticity with an HMAC signature. The internal
          // service key is never sent to third-party endpoints.
          'X-VulnTracker-Signature': sign(body),
        },
      });
      return { webhookId: webhook.id, success: true, attempt };
    } catch (err) {
      if (attempt === config.RETRY_ATTEMPTS) {
        return { webhookId: webhook.id, success: false, error: 'delivery failed', attempt };
      }
    }
  }
}

module.exports = { dispatch, sign };
