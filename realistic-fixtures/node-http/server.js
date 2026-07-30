// Realistic fixture #3: Node.js, built-in modules only, zero npm
// dependencies. Like the Go version — no artificial delay, just how
// secret comparisons are actually written in JS/TS, including
// AI-generated code (=== is the most common thing Copilot/Claude will
// write unless explicitly asked for timingSafeEqual).
//
// Run: node server.js
// Secret: "correct-secret-key-123456"

const http = require('http');
const crypto = require('crypto');

// Length is configurable via SECRET_LEN (25 by default, as before) —
// needed to find the secret length at which the real (not artificial)
// leak from === becomes large enough to see over an HTTP measurement,
// not just in isolation within the process.
function buildSecret(length) {
  const pattern = 'correct-secret-key-123456';
  let out = '';
  for (let i = 0; i < length; i++) out += pattern[i % pattern.length];
  return out;
}

const SECRET_LEN = parseInt(process.env.SECRET_LEN, 10) || 25;
const SECRET = buildSecret(SECRET_LEN);

function vulnerableCompare(candidate) {
  // the most common thing people actually write: a plain string
  // comparison. V8 compares strings character by character with an
  // early exit on the first mismatch — that's the exact leak channel,
  // with no amplification on our side.
  return candidate === SECRET;
}

function safeCompare(candidate) {
  const a = Buffer.from(candidate);
  const b = Buffer.from(SECRET);
  if (a.length !== b.length) return false; // timingSafeEqual requires equal length
  return crypto.timingSafeEqual(a, b);
}

const server = http.createServer((req, res) => {
  const candidate = req.headers['x-api-key'] || '';
  let ok = false;

  if (req.url === '/vulnerable') {
    ok = vulnerableCompare(candidate);
  } else if (req.url === '/safe') {
    ok = safeCompare(candidate);
  } else {
    res.writeHead(404);
    res.end();
    return;
  }

  res.writeHead(ok ? 200 : 401, { 'Content-Type': 'text/plain' });
  res.end(ok ? 'ok' : 'denied');
});

server.listen(8002, '0.0.0.0', () => {
  console.log('realistic Node fixture on http://0.0.0.0:8002 (reachable on any interface, not just loopback)');
  console.log('  /vulnerable — real === comparison, no artificial delay');
  console.log('  /safe       — crypto.timingSafeEqual');
  console.log(`  secret length: ${SECRET.length} bytes (set SECRET_LEN to change)`);
  console.log(`  secret: ${JSON.stringify(SECRET)}`);
});
