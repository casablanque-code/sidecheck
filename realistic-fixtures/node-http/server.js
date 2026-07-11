// Реалистичный полигон #3: Node.js, только встроенные модули, ноль npm-
// зависимостей. Как и Go-версия — никакой искусственной задержки, только
// то, как реально пишут сравнение секретов на JS/TS, включая AI-сгенерированный
// код (=== — самый частый способ, который увидит Copilot/Claude, если явно
// не попросить про timingSafeEqual).
//
// Запуск: node server.js
// Секрет: "correct-secret-key-123456"

const http = require('http');
const crypto = require('crypto');

const SECRET = 'correct-secret-key-123456';

function vulnerableCompare(candidate) {
  // самое частое, что реально пишут: обычное строковое сравнение.
  // V8 сравнивает строки посимвольно с ранним выходом на первом
  // несовпадении — тот самый канал утечки, без усилений с нашей стороны.
  return candidate === SECRET;
}

function safeCompare(candidate) {
  const a = Buffer.from(candidate);
  const b = Buffer.from(SECRET);
  if (a.length !== b.length) return false; // timingSafeEqual требует равной длины
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

server.listen(8002, '127.0.0.1', () => {
  console.log('realistic Node fixture on http://127.0.0.1:8002');
  console.log('  /vulnerable — real === comparison, no artificial delay');
  console.log('  /safe       — crypto.timingSafeEqual');
  console.log(`  secret: ${JSON.stringify(SECRET)}`);
});
