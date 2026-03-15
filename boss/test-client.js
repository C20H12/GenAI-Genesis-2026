const fs = require('fs/promises');
const path = require('path');
const WebSocket = require('ws');
const dotenv = require("dotenv");
dotenv.config();
const WS_URL = process.env.WS_URL || 'ws://localhost:8081';
const TEST_FILE = process.env.TEST_FILE || path.join(__dirname, 'test-domains.json');
const SEND_DELAY_MS = Number(process.env.SEND_DELAY_MS || 400);
const CLOSE_AFTER_MS = Number(process.env.CLOSE_AFTER_MS || 15000);


function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function loadPayloads() {
  const content = await fs.readFile(TEST_FILE, 'utf8');
  const payloads = JSON.parse(content);

  if (!Array.isArray(payloads)) {
    throw new Error('Test file must be a JSON array.');
  }

  return payloads;
}

async function main() {
  const payloads = await loadPayloads();
  const pending = new Set(
    payloads
      .map((p) => p && p.requestId)
      .filter((id) => typeof id === 'string' && id.length > 0)
  );

  const ws = new WebSocket(WS_URL);

  ws.on('open', async () => {
    console.log(`Connected to ${WS_URL}`);
    console.log(`Sending ${payloads.length} payload(s) from ${TEST_FILE}`);

    for (const payload of payloads) {
      ws.send(JSON.stringify(payload));
      await sleep(SEND_DELAY_MS);
    }
  });

  ws.on('message', (raw) => {
    let message;

    try {
      message = JSON.parse(raw.toString());
    } catch {
      console.log('[server:raw]', raw.toString());
      return;
    }

    console.log('[server]', message);

    if (message?.type === 'result' || message?.type === 'error') {
      if (typeof message.requestId === 'string') {
        pending.delete(message.requestId);
      }

      // if (pending.size === 0) {
      //   console.log('All requests completed. Closing connection.');
      //   ws.close(1000, 'done');
      // }
    }
  });

  ws.on('close', (code, reason) => {
    console.log(`Socket closed (${code}): ${reason.toString()}`);
    process.exit(0);
  });

  ws.on('error', (error) => {
    console.error('Socket error:', error.message);
    process.exit(1);
  });

  // setTimeout(() => {
  //   if (ws.readyState === WebSocket.OPEN) {
  //     console.log('Timeout reached; closing socket.');
  //     ws.close(1000, 'timeout');
  //   }
  // }, CLOSE_AFTER_MS);
}

main().catch((error) => {
  console.error('Test client failed:', error.message);
  process.exit(1);
});
