const puppeteer = require('puppeteer');
const { WebSocketServer, WebSocket } = require('ws');
const dotenv = require("dotenv");
dotenv.config();

const PORT = Number(process.env.WS_PORT || 8081);
const OPENROUTER_API_KEY = process.env.OPENROUTER_API_KEY;
const OPENROUTER_MODEL = process.env.OPENROUTER_MODEL || 'openai/gpt-4.1-mini';
const MAX_HTML_CHARS = Number(process.env.MAX_HTML_CHARS || 100000);
const queue = [];
let processing = false;

function normalizeUrl(domainOrUrl) {
  const trimmed = String(domainOrUrl || '').trim();
  if (!trimmed) {
    throw new Error('Domain is required.');
  }

  if (/^https?:\/\//i.test(trimmed)) {
    return trimmed;
  }

  return `https://${trimmed}`;
}

function extractTextContent(content) {
  if (typeof content === 'string') {
    return content;
  }

  if (Array.isArray(content)) {
    return content
      .map((part) => {
        if (typeof part === 'string') {
          return part;
        }
        if (part && typeof part.text === 'string') {
          return part.text;
        }
        return '';
      })
      .join(' ')
      .trim();
  }

  return '';
}

function clampHtmlForPrompt(html, maxChars) {
  if (typeof html !== 'string') {
    return '';
  }

  if (!Number.isFinite(maxChars) || maxChars <= 0) {
    return html;
  }

  if (html.length <= maxChars) {
    return html;
  }

  const headSize = Math.floor(maxChars * 0.8);
  const tailSize = Math.max(0, maxChars - headSize);
  const clippedHead = html.slice(0, headSize);
  const clippedTail = tailSize > 0 ? html.slice(-tailSize) : '';

  return `${clippedHead}\n<!-- HTML TRUNCATED: omitted middle content -->\n${clippedTail}`;
}

async function renderPageHtml(domain) {
  const url = normalizeUrl(domain);

  const browser = await puppeteer.launch({
    headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox']
  });

  try {
    const page = await browser.newPage();
    await page.setViewport({ width: 1440, height: 900 });
    await page.goto(url, { waitUntil: 'networkidle2', timeout: 30000 });
    const finalUrl = page.url();
    const title = await page.title();
    const renderedHtml = await page.content();

    return {
      finalUrl,
      title,
      renderedHtml
    };
  } finally {
    await browser.close();
  }
}

async function analyzeRenderedHtmlWithOpenRouter(domain, pageData) {
  if (!OPENROUTER_API_KEY) {
    throw new Error('Missing OPENROUTER_API_KEY environment variable.');
  }

  const clampedHtml = clampHtmlForPrompt(pageData.renderedHtml, MAX_HTML_CHARS);

  const requestBody = {
    model: OPENROUTER_MODEL,
    temperature: 0,
    response_format: { type: 'json_object' },
    messages: [
      {
        role: 'system',
        content: 'You are a website safety analyst. Return only strict JSON with keys: confidence (0-100 number) (higher = more like to be scam), reason (string).'
      },
      {
        role: 'user',
        content: `Domain to verify: ${domain}\nFinal URL: ${pageData.finalUrl}\nTitle: ${pageData.title}\nOriginal HTML length: ${pageData.renderedHtml.length}\nSent HTML length: ${clampedHtml.length}\n\nAnalyze this rendered HTML and decide if this page appears malicious (phishing, malware, scam, credential theft, fake support, drive-by download, impersonation).\n\nRendered HTML:\n${clampedHtml}`
      }
    ]
  };

  const response = await fetch('https://openrouter.ai/api/v1/chat/completions', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${OPENROUTER_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(requestBody)
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`OpenRouter request failed: ${response.status} ${text}`);
  }

  const payload = await response.json();
  const rawContent = payload?.choices?.[0]?.message?.content;
  const textContent = extractTextContent(rawContent);

  let parsed;
  try {
    parsed = JSON.parse(textContent);
  } catch {
    parsed = {
      confidence: 0,
      reason: `Model response was not valid JSON: ${textContent}`
    };
  }

  return {
    confidence: typeof parsed.confidence === 'number' ? parsed.confidence : 0,
    reason: typeof parsed.reason === 'string' ? parsed.reason : 'No reason provided by model.'
  };
}

function sendSocket(ws, message) {
  if (ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify(message));
  }
}

function enqueueJob(ws, domain, requestId) {
  queue.push({ ws, domain, requestId });
  sendSocket(ws, {
    type: 'queued',
    domain,
    requestId,
    queueSize: queue.length
  });
  void processQueue();
}

async function processQueue() {
  if (processing) {
    return;
  }

  processing = true;

  try {
    while (queue.length > 0) {
      const job = queue.shift();
      if (!job) {
        continue;
      }

      const { ws, domain, requestId } = job;

      try {
        sendSocket(ws, { type: 'processing', domain, requestId });
        const pageData = await renderPageHtml(domain);
        const aiResult = await analyzeRenderedHtmlWithOpenRouter(domain, pageData);

        sendSocket(ws, {
          type: 'result',
          domain,
          requestId,
          result: aiResult
        });
      } catch (error) {
        sendSocket(ws, {
          type: 'error',
          domain,
          requestId,
          error: error instanceof Error ? error.message : String(error)
        });
      }
    }
  } finally {
    processing = false;
  }
}

async function start() {
  const wss = new WebSocketServer({ port: PORT, host:"0.0.0.0" });

  wss.on('connection', (ws) => {
    sendSocket(ws, {
      type: 'welcome',
      message: 'Send JSON {"type":"verify-domain","domain":"example.com","requestId":"optional"}'
    });

    ws.on('message', (raw) => {
      let message;
      try {
        message = JSON.parse(raw.toString());
      } catch {
        sendSocket(ws, { type: 'error', error: 'Message must be valid JSON.' });
        return;
      }

      if (message?.type !== 'verify-domain') {
        sendSocket(ws, { type: 'error', error: 'Unsupported message type.' });
        return;
      }

      const domain = String(message.domain || '').trim();
      if (!domain) {
        sendSocket(ws, { type: 'error', error: 'Field "domain" is required.' });
        return;
      }

      enqueueJob(ws, domain, message.requestId || null);
    });
  });

  console.log(`Domain verifier websocket server is running on ws://localhost:${PORT}`);
}

start().catch((error) => {
  console.error('Failed to start domain verifier:', error);
  process.exitCode = 1;
});
