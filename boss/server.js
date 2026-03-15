const path = require('path');
const fs = require('fs/promises');
const puppeteer = require('puppeteer');
const express = require('express');
const { WebSocketServer, WebSocket } = require('ws');
const dotenv = require('dotenv');

dotenv.config();

const PORT = Number(process.env.WS_PORT || 8081);
const WEB_PORT = Number(process.env.WEB_PORT || 8082);
const OPENROUTER_API_KEY = process.env.OPENROUTER_API_KEY;
const OPENROUTER_MODEL = process.env.OPENROUTER_MODEL || "deepseek/deepseek-v3.2";
const MAX_HTML_CHARS = Number(process.env.MAX_HTML_CHARS || 100000);
const RESULTS_FILE = path.join(__dirname, 'results.json');
const SCREENSHOTS_DIR = path.join(__dirname, 'screenshots');
const queue = [];
const activeJobs = new Map();
let resultsWriteQueue = Promise.resolve();
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

function normalizeScore(value) {
  const num = Number(value);
  if (!Number.isFinite(num)) {
    return 0;
  }

  if (num < 0) {
    return 0;
  }

  if (num > 100) {
    return 100;
  }

  return Math.round(num);
}

function safeFileName(value) {
  return String(value || '')
    .toLowerCase()
    .replace(/[^a-z0-9.-]/g, '_')
    .slice(0, 120);
}

function toPageKey(domainOrUrl) {
  const normalized = normalizeUrl(domainOrUrl);
  const parsed = new URL(normalized);
  const path = parsed.pathname || '/';
  return `${parsed.hostname}${path}`.toLowerCase();
}

async function readSavedResults() {
  try {
    const raw = await fs.readFile(RESULTS_FILE, 'utf8');
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch (error) {
    if (error && error.code === 'ENOENT') {
      return [];
    }

    console.error('Failed to read results file:', error);
    return [];
  }
}

function saveResultRecord(record) {
  resultsWriteQueue = resultsWriteQueue
    .then(async () => {
      const current = await readSavedResults();
      current.unshift(record);
      await fs.writeFile(RESULTS_FILE, JSON.stringify(current.slice(0, 500), null, 2), 'utf8');
    })
    .catch((error) => {
      console.error('Failed to write results file:', error);
    });

  return resultsWriteQueue;
}

async function findCachedResult(domainOrUrl) {
  // Ensure in-flight writes are visible before cache lookup.
  await resultsWriteQueue;

  const targetPageKey = toPageKey(domainOrUrl);
  const targetRaw = String(domainOrUrl || '').trim().toLowerCase();
  const saved = await readSavedResults();

  return saved.find((entry) => {
    const entryDomain = String(entry.domain || '').trim().toLowerCase();
    const entryPageKey = String(entry.pageKey || '').trim().toLowerCase();

    if (entryPageKey && entryPageKey === targetPageKey) {
      return true;
    }

    if (entryDomain === targetRaw) {
      return true;
    }

    try {
      return toPageKey(entry.domain || '') === targetPageKey;
    } catch {
      return false;
    }
  });
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
    const screenshotFileName = `${safeFileName(domain)}-${Date.now()}.png`;
    const screenshotFsPath = path.join(SCREENSHOTS_DIR, screenshotFileName);
    await page.screenshot({ path: screenshotFsPath, fullPage: true });
    const pageBody = await page.evaluate(() => {
      const body = document.body;
      if (!body) {
        return { bodyHtml: '', bodyText: '' };
      }

      const clone = body.cloneNode(true);
      clone.querySelectorAll('script,style,noscript,template').forEach((node) => node.remove());

      const bodyHtml = clone.innerHTML || '';
      const bodyText = (clone.innerText || clone.textContent || '')
        .replace(/\s+/g, ' ')
        .trim();

      return { bodyHtml, bodyText };
    });

    return {
      finalUrl,
      title,
      screenshotPath: `/screenshots/${screenshotFileName}`,
      bodyHtml: pageBody.bodyHtml,
      bodyText: pageBody.bodyText
    };
  } finally {
    await browser.close();
  }
}

async function analyzeRenderedHtmlWithOpenRouter(domain, pageData) {
  if (!OPENROUTER_API_KEY) {
    throw new Error('Missing OPENROUTER_API_KEY environment variable.');
  }

  const clampedBodyHtml = clampHtmlForPrompt(pageData.bodyHtml, MAX_HTML_CHARS);
  const clampedBodyText = clampHtmlForPrompt(pageData.bodyText, MAX_HTML_CHARS);

  const requestBody = {
    model: OPENROUTER_MODEL,
    temperature: 0,
    response_format: { type: 'json_object' },
    messages: [
      {
        role: 'system',
        content: 'You are a website safety analyst. Return only strict JSON with keys: confidence (0-100 number) (higher = more likely to be scam), reason (string).'
      },
      {
        role: 'user',
        content: `Domain to verify: ${domain}\nFinal URL: ${pageData.finalUrl}\nTitle: ${pageData.title}\nOriginal body HTML length: ${pageData.bodyHtml.length}\nSent body HTML length: ${clampedBodyHtml.length}\nOriginal body text length: ${pageData.bodyText.length}\nSent body text length: ${clampedBodyText.length}\n\nAnalyze this content and decide if this page appears malicious (phishing, malware, scam, credential theft, fake support, drive-by download, impersonation).\n\nBody HTML (filtered):\n${clampedBodyHtml}\n\nVisible Body Text (filtered):\n${clampedBodyText}`
      }
    ]
  };

  const response = await fetch('https://openrouter.ai/api/v1/chat/completions', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${OPENROUTER_API_KEY}`,
      'Content-Type': 'application/json'
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

async function getDashboardState() {
  const processingDomains = Array.from(activeJobs.values()).map((job) => ({
    domain: job.domain,
    requestId: job.requestId,
    startedAt: job.startedAt
  }));

  const queuedDomains = queue.map((job) => ({
    domain: job.domain,
    requestId: job.requestId
  }));

  const results = await readSavedResults();

  return {
    processing: processingDomains,
    queued: queuedDomains,
    results,
    queueSize: queue.length,
    activeCount: activeJobs.size,
    updatedAt: new Date().toISOString()
  };
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
      const jobKey = `${requestId ?? 'no-id'}:${domain}:${Date.now()}`;
      activeJobs.set(jobKey, {
        domain,
        requestId,
        startedAt: new Date().toISOString()
      });

      try {
        sendSocket(ws, { type: 'processing', domain, requestId });

        const cached = await findCachedResult(domain);
        if (cached) {
          sendSocket(ws, {
            type: 'result',
            domain,
            requestId,
            result: {
              confidence: normalizeScore(cached.score),
              reason: cached.reason || 'Loaded from cache',
              cached: true
            }
          });
          continue;
        }

        const pageData = await renderPageHtml(domain);
        const aiResult = await analyzeRenderedHtmlWithOpenRouter(domain, pageData);

        sendSocket(ws, {
          type: 'result',
          domain,
          requestId,
          result: aiResult
        });

        void saveResultRecord({
          domain,
          pageKey: toPageKey(domain),
          score: normalizeScore(aiResult.confidence),
          reason: aiResult.reason,
          screenshotPath: pageData.screenshotPath,
          createdAt: new Date().toISOString()
        });
      } catch (error) {
        sendSocket(ws, {
          type: 'error',
          domain,
          requestId,
          error: error instanceof Error ? error.message : String(error)
        });
      } finally {
        activeJobs.delete(jobKey);
      }
    }
  } finally {
    processing = false;
  }
}

async function start() {
  const app = express();

  await fs.mkdir(SCREENSHOTS_DIR, { recursive: true });

  app.use('/screenshots', express.static(SCREENSHOTS_DIR));

  app.get('/status', async (_req, res) => {
    res.json(await getDashboardState());
  });

  app.get('/', (_req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
  });

  app.listen(WEB_PORT, '0.0.0.0', () => {
    console.log(`Dashboard running at http://0.0.0.0:${WEB_PORT}`);
  });

  const wss = new WebSocketServer({ port: PORT, host: '0.0.0.0' });

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

  console.log(`Domain verifier websocket server is running on :${PORT}`);
}

start().catch((error) => {
  console.error('Failed to start domain verifier:', error);
  process.exitCode = 1;
});
