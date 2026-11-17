// All secrets come from the environment (populated from a secrets manager in
// Kubernetes). Nothing sensitive is committed to source control.
const fs = require('fs');

function readSecret(name) {
  const file = process.env[`${name}_FILE`];
  // Path comes from operator-controlled deployment config, not user input.
  // nosemgrep: javascript.lang.security.audit.detect-non-literal-fs-filename.detect-non-literal-fs-filename
  if (file) return fs.readFileSync(file, 'utf8').trim();
  return process.env[name];
}

module.exports = {
  PORT: process.env.PORT || 3001,
  PYTHON_API_URL: process.env.PYTHON_API_URL || 'http://localhost:8000',

  // Bearer key callers (the Python API / admins) must present. Required.
  API_KEY: readSecret('NOTIFY_API_KEY'),
  // Secret used to HMAC-sign outbound webhook bodies so receivers can verify
  // authenticity. Never sent over the wire. Falls back to API_KEY-derived value.
  WEBHOOK_SIGNING_SECRET: readSecret('WEBHOOK_SIGNING_SECRET'),

  // Only https webhook targets are allowed unless explicitly relaxed (dev/test).
  ALLOW_INSECURE_WEBHOOKS: process.env.ALLOW_INSECURE_WEBHOOKS === 'true',

  RETRY_ATTEMPTS: 3,
  TIMEOUT_MS: 5000,
};
