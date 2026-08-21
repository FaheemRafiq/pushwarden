const http = require('http');
const fs = require('fs');
const path = require('path');

const OUTPUT_DIR = '/analysis/output';
const LOG_FILE = path.join(OUTPUT_DIR, 'c2-intercept.log');

function log(msg) {
  const line = `[${new Date().toISOString()}] ${msg}`;
  console.log(line);
  fs.appendFileSync(LOG_FILE, line + '\n');
}

const responses = {
  '/ls': JSON.stringify({ status: 'ok', version: 'A10-*23650' }),
  '/cl': JSON.stringify({ status: 'ok', commands: [] }),
  '/0x': JSON.stringify({
    eval: 'console.log("[C2-MOCK] Stage 2 payload executed")'
  }),
};

function xorDecrypt(buffer, key) {
  const result = Buffer.alloc(buffer.length);
  for (let i = 0; i < buffer.length; i++) {
    result[i] = buffer[i] ^ key[i % key.length];
  }
  return result;
}

const server = http.createServer((req, res) => {
  const secV = req.headers['sec-v'] || 'none';
  const ua = req.headers['user-agent'] || 'none';
  const encoding = req.headers['content-encoding'] || 'none';
  const payloadHeader = req.headers['x-payload'] || 'none';

  log(`REQUEST: ${req.method} ${req.url}`);
  log(`  Headers:`);
  log(`    Sec-V: ${secV}`);
  log(`    User-Agent: ${ua}`);
  log(`    Content-Encoding: ${encoding}`);
  log(`    X-Payload: ${payloadHeader}`);
  log(`    Host: ${req.headers.host}`);
  log(`    Connection: ${req.headers.connection}`);

  let body = [];
  req.on('data', chunk => {
    body.push(chunk);
    log(`  Body chunk: ${chunk.length} bytes`);
  });

  req.on('end', () => {
    const fullBody = Buffer.concat(body);
    if (fullBody.length > 0) {
      log(`  Total body: ${fullBody.length} bytes`);
      log(`  Body hex: ${fullBody.toString('hex').substring(0, 200)}`);

      if (secV !== 'none') {
        const decrypted = xorDecrypt(fullBody, Buffer.from(secV));
        log(`  Decrypted body: ${decrypted.toString('utf8').substring(0, 500)}`);
      }
    }

    let responsePath = req.url.split('?')[0];
    let responseBody = responses[responsePath] || JSON.stringify({ status: 'mock', path: responsePath });

    if (responseBody) {
      log(`  Response: ${responseBody.substring(0, 200)}`);
    }

    res.writeHead(200, {
      'Content-Type': 'application/json',
      'X-Payload': 'mock-response',
    });
    res.end(responseBody);
  });

  req.on('error', (e) => {
    log(`  ERROR: ${e.message}`);
  });
});

server.listen(4443, '0.0.0.0', () => {
  log('[MOCK-C2] C2 server mock listening on port 4443');
  log('[MOCK-C2] All requests will be logged and intercepted');
  log('[MOCK-C2] XOR decryption will be attempted using Sec-V header as key');
});

process.on('uncaughtException', (e) => {
  log(`[FATAL] ${e.message}`);
});
