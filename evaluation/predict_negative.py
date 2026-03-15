# # Fraud Detection Evaluation
# 
# This notebook evaluates domains from `dataset.csv` using the same fraud detection logic as `fraud.go`:
# 1. Fetches each domain via Selenium (headless Chrome) for full JS rendering
# 2. Extracts visible text (strips script/style/noscript)
# 3. Calls OpenRouter API (deepseek/deepseek-v3.2) with the fraud detection prompt
# 4. Stores `prediction` (score 0-100) and `reasoning` in the output CSV
# 
# **Parallel processing** — uses a thread pool with multiple Selenium drivers to process domains concurrently.


import pandas as pd
import numpy as np
import os
import json
import time
import threading
import traceback
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.common.exceptions import TimeoutException, WebDriverException


# ---- Configuration ----
def load_env(path='.env'):
    env = {}
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                key, _, value = line.partition('=')
                value = value.strip().strip('"').strip("'")
                env[key.strip()] = value
    except FileNotFoundError:
        pass
    return env

env = load_env()
OPENROUTER_API_KEY = env.get('APIKEY', os.environ.get('OPENROUTER_API_KEY', ''))
assert OPENROUTER_API_KEY, 'API key not found — check .env file has APIKEY=...'
print(f'API key loaded: {OPENROUTER_API_KEY[:8]}...{OPENROUTER_API_KEY[-4:]}')
print(f'API key length: {len(OPENROUTER_API_KEY)}')

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
FRAUD_MODEL = "deepseek/deepseek-v3.2"
PAGE_LOAD_TIMEOUT = 15   # seconds for Selenium
TEXT_TRUNCATION = 8000   # chars, same as fraud.go
MAX_WORKERS = 10         # number of parallel threads/browsers
SAVE_INTERVAL = 10       # save results every N completed domains


# ---- Quick API Smoke Test ----
# Test the API key with a minimal request before running the full dataset
print("Testing API connection...")
test_body = {
    "model": FRAUD_MODEL,
    "messages": [{"role": "user", "content": "Say hello in 3 words"}],
}
test_headers = {
    "Content-Type": "application/json",
    "Authorization": f"Bearer {OPENROUTER_API_KEY}",
}
test_resp = requests.post(OPENROUTER_URL, json=test_body, headers=test_headers, timeout=30)
print(f"Status: {test_resp.status_code}")
print(f"Response: {test_resp.text[:500]}")
if test_resp.status_code == 200:
    print("✅ API key works!")
else:
    print("❌ API key or request is broken — fix before proceeding")


# ---- Prompt (identical to fraud.go) ----
PROMPT = """
You are a fraud detection assistant.
Analyze the following webpage text and determine if it is fraudulent.

Analyze from the following aspects:
- Does the content match the official domain?
- Is the website gambling related?
- Does it claim unrealistic financial returns?
- Does it claim high user count, even it's unheard of?
- Does it have obviously fake testimonials?

To prevent false positive:
- A less well known website does not mean it's a scam. Only classify as fraud if there are clear signs of fraud (as listed above).
- A generic error (4xx, 5xx) / redirection / loading page does not mean it's a scam.

Return a fraud score from 0 (not fraud) to 100 (definitely fraud) and a brief reason, in JSON.
""".strip()


# ---- Selenium Driver Pool (thread-local) ----
_thread_local = threading.local()
_all_drivers = []  # track all drivers for cleanup
_drivers_lock = threading.Lock()

def get_driver():
    """Get or create a thread-local headless Chrome driver."""
    driver = getattr(_thread_local, 'driver', None)
    if driver is None:
        chrome_options = Options()
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--window-size=1920,1080")
        chrome_options.add_argument("--disable-extensions")
        chrome_options.add_argument("--disable-notifications")
        chrome_options.add_argument(
            "--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        )
        driver = webdriver.Chrome(options=chrome_options)
        driver.set_page_load_timeout(PAGE_LOAD_TIMEOUT)
        _thread_local.driver = driver
        with _drivers_lock:
            _all_drivers.append(driver)
        print(f"    [thread {threading.current_thread().name}] Chrome driver created")
    return driver

def cleanup_drivers():
    """Quit all created drivers."""
    with _drivers_lock:
        for d in _all_drivers:
            try:
                d.quit()
            except Exception:
                pass
        _all_drivers.clear()


# ---- HTML Text Extraction (mirrors fraud.go's extractText) ----
def extract_text(html: str) -> str:
    """Extract visible text from HTML, skipping script/style/noscript."""
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup.find_all(["script", "style", "noscript"]):
        tag.decompose()
    text = soup.get_text(separator=" ", strip=True)
    text = "".join(c for c in text if c.isprintable() or c.isspace())
    return text.strip()


# ---- Fetch Page HTML via Selenium ----
def fetch_page_html(domain: str) -> str | None:
    """Navigate to domain via thread-local Selenium driver, return rendered HTML."""
    url = f"https://{domain}"
    driver = get_driver()
    try:
        driver.get(url)
        time.sleep(2)  # let JS render
        html = driver.page_source
        print(f"    [fetch] {domain}: got {len(html)} bytes HTML")
        return html
    except TimeoutException:
        print(f"    [fetch] {domain}: TIMEOUT, trying to get partial page_source")
        try:
            return driver.page_source
        except Exception:
            return None
    except WebDriverException as e:
        print(f"    [fetch] {domain}: WebDriverException: {str(e)[:150]}")
        return None
    except Exception as e:
        print(f"    [fetch] {domain}: unexpected error: {type(e).__name__}: {e}")
        return None


# ---- OpenRouter LLM Call (mirrors fraud.go's callFraudLLM) ----
def call_fraud_llm(url: str, text: str) -> dict | None:
    """Call OpenRouter API with the same request format as fraud.go.
    Returns {'score': int, 'reason': str} or None on failure."""
    if len(text) > TEXT_TRUNCATION:
        text = text[:TEXT_TRUNCATION]

    req_body = {
        "model": FRAUD_MODEL,
        "messages": [
            {"role": "system", "content": PROMPT},
            {"role": "user", "content": f"URL: {url}\n\nPage text:\n{text}"},
        ],
        "response_format": {
            "type": "json_schema",
            "json_schema": {
                "name": "fraud_detection",
                "strict": True,
                "schema": {
                    "type": "object",
                    "properties": {
                        "reason": {
                            "type": "string",
                            "description": "Brief explanation of the fraud assessment",
                        },
                        "score": {
                            "type": "integer",
                            "description": "Fraud score from 0 (not fraud) to 100 (definitely fraud)",
                        },
                    },
                    "required": ["score", "reason"],
                    "additionalProperties": False,
                },
            },
        },
    }

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {OPENROUTER_API_KEY}",
    }

    try:
        print(f"    [llm] {url}: sending request (text length: {len(text)} chars)")
        resp = requests.post(OPENROUTER_URL, json=req_body, headers=headers, timeout=60)
        
        # Log status code like fraud.go does
        if resp.status_code != 200:
            print(f"    [llm] {url}: ❌ openrouter returned {resp.status_code}: {resp.text[:500]}")
            return None

        resp_body = resp.text
        print(f"    [llm] {url}: got response ({len(resp_body)} bytes)")

        # Parse completion response (same structure as fraud.go)
        completion = resp.json()
        choices = completion.get("choices", [])
        if not choices:
            print(f"    [llm] {url}: ❌ no choices in response: {resp_body[:300]}")
            return None

        content = choices[0]["message"]["content"]
        print(f"    [llm] {url}: raw content: {content[:200]}")

        # Parse the JSON result
        result = json.loads(content)
        score = result["score"]
        reason = result["reason"]
        print(f"    [llm] {url}: ✅ score={score}, reason={reason[:80]}")
        return {"score": score, "reason": reason}

    except requests.exceptions.Timeout:
        print(f"    [llm] {url}: ❌ request timed out after 60s")
        return None
    except json.JSONDecodeError as e:
        print(f"    [llm] {url}: ❌ JSON decode error: {e}")
        print(f"    [llm] {url}: raw response was: {resp.text[:500]}")
        return None
    except KeyError as e:
        print(f"    [llm] {url}: ❌ missing key {e} in response")
        print(f"    [llm] {url}: parsed content was: {content[:300]}")
        return None
    except Exception as e:
        print(f"    [llm] {url}: ❌ unexpected error: {type(e).__name__}: {e}")
        traceback.print_exc()
        return None


# ---- Single Domain Pipeline ----
def process_domain(domain: str) -> dict:
    """Full pipeline for one domain: fetch → extract → LLM → result."""
    url = f"https://{domain}"
    
    # Step 1: Fetch rendered HTML
    html = fetch_page_html(domain)
    if html is None:
        return {"domain": domain, "prediction": -1, "reasoning": "ERROR: Could not fetch page"}

    # Step 2: Extract visible text
    text = extract_text(html)
    if not text.strip():
        return {"domain": domain, "prediction": -1, "reasoning": "ERROR: Empty page text"}
    
    print(f"    [extract] {domain}: {len(text)} chars of visible text")

    # Step 3: Call LLM
    result = call_fraud_llm(url, text)
    if result is None:
        return {"domain": domain, "prediction": -1, "reasoning": "ERROR: API call failed"}

    return {"domain": domain, "prediction": result["score"], "reasoning": result["reason"]}


# ---- Load Dataset ----
df = pd.read_csv("dataset.csv")
print(f"Loaded {len(df)} domains")

if "prediction" not in df.columns:
    df["prediction"] = np.nan
if "reasoning" not in df.columns:
    df["reasoning"] = ""

# ---- Resume from existing results (skip errors to retry them) ----
RESULTS_FILE = "results.csv"

if os.path.exists(RESULTS_FILE):
    existing = pd.read_csv(RESULTS_FILE)
    for _, row in existing.iterrows():
        if pd.notna(row.get("prediction")) and row["prediction"] >= 0:
            mask = df["domain"] == row["domain"]
            df.loc[mask, "prediction"] = row["prediction"]
            df.loc[mask, "reasoning"] = row["reasoning"]
    already_done = df["prediction"].notna().sum()
    print(f"Resumed: {already_done}/{len(df)} already successfully processed (errors will be retried)")
else:
    print("Starting fresh")

pending = df[df["prediction"].isna()]
print(f"Pending: {len(pending)} domains to process with {MAX_WORKERS} parallel workers")


# ---- Parallel Evaluation Loop ----
pending_domains = list(pending["domain"])
pending_indices = list(pending.index)
total = len(pending_domains)
completed = 0
results_lock = threading.Lock()

print(f"Starting parallel evaluation: {total} domains, {MAX_WORKERS} workers\n")

try:
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        # Submit all tasks
        future_to_idx = {}
        for idx, domain in zip(pending_indices, pending_domains):
            future = executor.submit(process_domain, domain)
            future_to_idx[future] = idx

        # Collect results as they complete
        for future in as_completed(future_to_idx):
            idx = future_to_idx[future]
            try:
                result = future.result()
                with results_lock:
                    df.at[idx, "prediction"] = result["prediction"]
                    df.at[idx, "reasoning"] = result["reasoning"]
                    completed += 1

                status = "✅" if result["prediction"] >= 0 else "⚠"
                score_str = str(result["prediction"]) if result["prediction"] >= 0 else "ERR"
                reason_preview = result["reasoning"][:60]
                print(f"  {status} [{completed}/{total}] {result['domain']} → {score_str} | {reason_preview}")

                # Periodic save
                if completed % SAVE_INTERVAL == 0:
                    with results_lock:
                        df.to_csv(RESULTS_FILE, index=False)
                    print(f"  💾 Progress saved ({completed}/{total})")

            except Exception as e:
                with results_lock:
                    df.at[idx, "prediction"] = -1
                    df.at[idx, "reasoning"] = f"ERROR: {type(e).__name__}: {e}"
                    completed += 1
                print(f"  ❌ [{completed}/{total}] index {idx} failed: {type(e).__name__}: {e}")
                traceback.print_exc()

finally:
    cleanup_drivers()
    df.to_csv(RESULTS_FILE, index=False)
    print(f"\n💾 Final results saved to {RESULTS_FILE}")
    print(f"Completed: {completed}/{total}")


# ---- Results Summary ----
results = pd.read_csv(RESULTS_FILE)
valid = results[results["prediction"] >= 0]
errors = results[results["prediction"] < 0]

print(f"Total domains: {len(results)}")
print(f"Successfully evaluated: {len(valid)}")
print(f"Errors/skipped: {len(errors)}")
print(f"\nScore distribution:")
print(valid["prediction"].describe())
print(f"\nDomains flagged as fraud (score >= 65): {len(valid[valid['prediction'] >= 65])}")
print(f"\nTop 10 highest scores:")
print(valid.nlargest(10, 'prediction')[['domain', 'is_scam', 'prediction', 'reasoning']])

