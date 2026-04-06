"""
Brainrot Auto-Join Relay Server (ENCRYPTED)
Uses Discord REST API directly (no discord.py) to avoid Cloudflare gateway blocks.
Polls channel for new messages every 2 seconds, serves encrypted data over HTTP.
"""

import os
import re
import time
import asyncio
import base64
import hashlib
import secrets
import json
import urllib.parse
from aiohttp import web, ClientSession, TCPConnector

# ─── CONFIG ───
DISCORD_TOKEN  = os.environ["DISCORD_TOKEN"]
CHANNEL_ID     = os.environ["CHANNEL_ID"]
API_KEY        = os.environ["API_KEY"]
ENCRYPTION_KEY = os.environ["ENCRYPTION_KEY"]
PORT           = int(os.environ.get("PORT", 10000))
POLL_INTERVAL  = 2  # seconds between Discord API polls

DISCORD_API    = "https://discord.com/api/v10"
HEADERS        = {
    "Authorization": f"Bot {DISCORD_TOKEN}",
    "User-Agent": "DiscordBot (https://github.com/brainrot-relay, 1.0.0)",
    "Content-Type": "application/json",
}

# ─── STORAGE ───
detections = []
detection_counter = 0
MAX_DETECTIONS = 50
start_time = time.time()
last_message_id = None
bot_ready = False

# ─── ENCRYPTION ───

def derive_key(nonce_bytes):
    return hashlib.sha256(ENCRYPTION_KEY.encode() + nonce_bytes).digest()

def encrypt_string(plaintext):
    if not plaintext:
        return ""
    nonce = secrets.token_bytes(16)
    key = derive_key(nonce)
    plain_bytes = plaintext.encode("utf-8")
    cipher_bytes = bytes([b ^ key[i % len(key)] for i, b in enumerate(plain_bytes)])
    return base64.b64encode(nonce + cipher_bytes).decode("ascii")

# ─── AUTH ───

def check_api_key(request):
    key = request.headers.get("X-API-Key") or request.query.get("key")
    return key == API_KEY

# ─── PARSING ───

def parse_roblox_url(url):
    place_id = None
    server_id = None

    m = re.search(r'placeId[=:](\d+)', url)
    if m:
        place_id = m.group(1)
    if not place_id:
        m = re.search(r'/games/(\d+)', url)
        if m:
            place_id = m.group(1)

    m = re.search(r'(?:gameInstanceId|serverJobId)[=:]([a-f0-9-]+)', url, re.IGNORECASE)
    if m:
        server_id = m.group(1)

    m = re.search(r'launchData=([^&]+)', url)
    if m:
        launch_data = urllib.parse.unquote(m.group(1))
        m2 = re.search(r'serverJobId[=:]([a-f0-9-]+)', launch_data, re.IGNORECASE)
        if m2:
            server_id = m2.group(1)

    return place_id, server_id


def clean_markdown(text):
    """Strip Discord markdown and custom emojis from text."""
    if not text:
        return ""
    # Remove custom emojis like <:MutDiamond:1486451234> or <a:animated:123>
    text = re.sub(r'<a?:\w+:\d+>', '', text)
    # Remove bold/italic markdown
    text = text.replace("**", "").replace("__", "").replace("*", "").replace("_", "")
    # Remove └ prefix
    text = text.replace("└", "").replace("├", "")
    # Clean whitespace
    text = " ".join(text.split()).strip()
    return text


def extract_money_value(text):
    """Extract money/value from text like '14.5M/s', '100M+', '2.3B'."""
    if not text:
        return ""
    # Look for patterns like 14.5M/s, 100M, 2.3B/s, 500K/s, etc.
    m = re.search(r'([\d,.]+\s*[KMBTkmbt](?:\+|/s)?)', text)
    if m:
        return m.group(1).strip()
    # Look for just numbers
    m = re.search(r'([\d,.]+)', text)
    if m:
        return m.group(1).strip()
    return ""


def parse_discord_message(msg):
    """Parse a Discord API message JSON for brainrot data."""
    global detection_counter
    results = []

    # Extract join URLs from components (buttons)
    join_urls = []
    for row in msg.get("components", []):
        for comp in row.get("components", []):
            url = comp.get("url", "")
            if url and "roblox" in url.lower():
                join_urls.append(url)

    # Also check message content for roblox URLs
    content = msg.get("content", "")
    for url_match in re.finditer(r'https?://\S*roblox\S*', content, re.IGNORECASE):
        join_urls.append(url_match.group(0))

    for i, embed in enumerate(msg.get("embeds", [])):
        data = {
            "brainrot_name": "",
            "value": "",
            "server_id": "",
            "place_id": "",
            "raw_server_id": "",
            "timestamp": time.time(),
        }

        # ─── PARSE EMBED FIELDS ───
        for field in embed.get("fields", []):
            nl = field.get("name", "").lower()
            val = field.get("value", "")
            if any(k in nl for k in ["brainrot", "name", "item", "pet"]):
                data["brainrot_name"] = clean_markdown(val)
            elif any(k in nl for k in ["value", "price", "worth", "rap", "cost", "money", "m/s", "/s"]):
                data["value"] = clean_markdown(val)
                if not data["value"]:
                    data["value"] = extract_money_value(val)
            elif any(k in nl for k in ["server", "link", "job", "id"]):
                if not data["raw_server_id"]:
                    data["raw_server_id"] = val.strip()

        # ─── PARSE DESCRIPTION ───
        desc = embed.get("description", "")
        if desc:
            lines = desc.strip().split("\n")
            
            # Try to extract brainrot name from first line (usually **Name**)
            if not data["brainrot_name"] and lines:
                first_line = clean_markdown(lines[0])
                if first_line:
                    data["brainrot_name"] = first_line

            # Try to extract value from remaining lines
            if not data["value"]:
                for line in lines[1:]:
                    val = extract_money_value(line)
                    if val:
                        data["value"] = val
                        break

            # If still no value, try the whole description
            if not data["value"]:
                data["value"] = extract_money_value(desc)

        # ─── PARSE TITLE AS NAME FALLBACK ───
        title = embed.get("title") or ""
        if not data["brainrot_name"] and title:
            data["brainrot_name"] = clean_markdown(title)

        # ─── EXTRACT SERVER/PLACE ID FROM BUTTON URLS ───
        url = join_urls[i] if i < len(join_urls) else (join_urls[0] if join_urls else "")
        if url:
            pid, sid = parse_roblox_url(url)
            if pid:
                data["place_id"] = pid
            if sid and not data["raw_server_id"]:
                data["raw_server_id"] = sid

        # Encrypt server_id
        data["server_id"] = encrypt_string(data["raw_server_id"])

        detection_counter += 1
        data["id"] = detection_counter
        results.append(data)

    return results


# ─── DISCORD POLLER ───

async def poll_discord(session):
    """Poll Discord channel for new messages every POLL_INTERVAL seconds."""
    global last_message_id, bot_ready

    print(f"[POLLER] Starting — watching channel {CHANNEL_ID}", flush=True)

    # Get the latest message ID to start from (so we don't process old messages)
    try:
        url = f"{DISCORD_API}/channels/{CHANNEL_ID}/messages?limit=1"
        async with session.get(url, headers=HEADERS) as resp:
            if resp.status == 200:
                msgs = await resp.json()
                if msgs:
                    last_message_id = msgs[0]["id"]
                    print(f"[POLLER] Starting after message {last_message_id}", flush=True)
                bot_ready = True
                print("[POLLER] Ready! Watching for new detections...", flush=True)
            else:
                text = await resp.text()
                print(f"[POLLER] Error fetching initial messages: {resp.status} — {text}", flush=True)
                return
    except Exception as e:
        print(f"[POLLER] Error on startup: {e}", flush=True)
        return

    # Main polling loop
    while True:
        try:
            await asyncio.sleep(POLL_INTERVAL)

            url = f"{DISCORD_API}/channels/{CHANNEL_ID}/messages?limit=10"
            if last_message_id:
                url += f"&after={last_message_id}"

            async with session.get(url, headers=HEADERS) as resp:
                if resp.status == 200:
                    msgs = await resp.json()
                    if msgs:
                        # Messages come newest first, reverse to process oldest first
                        msgs.reverse()
                        for msg in msgs:
                            if msg.get("embeds"):
                                results = parse_discord_message(msg)
                                for d in results:
                                    detections.append(d)
                                    print(f"[DETECTION] #{d['id']} | {d['brainrot_name']} | {d['value']}", flush=True)

                                while len(detections) > MAX_DETECTIONS:
                                    detections.pop(0)

                            last_message_id = msg["id"]

                elif resp.status == 429:
                    # Rate limited
                    data = await resp.json()
                    wait = data.get("retry_after", 5)
                    print(f"[POLLER] Rate limited, waiting {wait}s", flush=True)
                    await asyncio.sleep(wait)
                else:
                    text = await resp.text()
                    print(f"[POLLER] Error: {resp.status} — {text[:200]}", flush=True)
                    await asyncio.sleep(10)

        except Exception as e:
            print(f"[POLLER] Exception: {e}", flush=True)
            await asyncio.sleep(5)


# ─── HTTP SERVER ───

def sanitize_detection(d):
    return {k: v for k, v in d.items() if k != "raw_server_id"}

async def handle_root(request):
    return web.Response(
        text="Brainrot Relay is running! Use /latest or /detections (API key required)",
        content_type="text/plain",
    )

async def handle_latest(request):
    if not check_api_key(request):
        return web.json_response({"error": "unauthorized"}, status=401)
    if detections:
        return web.json_response(sanitize_detection(detections[-1]))
    return web.json_response({"found": False})

async def handle_detections(request):
    if not check_api_key(request):
        return web.json_response({"error": "unauthorized"}, status=401)
    after_id = int(request.query.get("after_id", 0))
    new = [sanitize_detection(d) for d in detections if d["id"] > after_id]
    return web.json_response({"detections": new, "count": len(new)})

async def handle_health(request):
    return web.json_response({
        "status": "ok",
        "bot_ready": bot_ready,
        "uptime_seconds": round(time.time() - start_time),
        "detections_count": len(detections),
    })

async def start_http():
    app = web.Application()
    app.router.add_get("/", handle_root)
    app.router.add_get("/latest", handle_latest)
    app.router.add_get("/detections", handle_detections)
    app.router.add_get("/health", handle_health)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", PORT)
    await site.start()
    print(f"[HTTP] Server running on port {PORT}", flush=True)


# ─── MAIN ───

async def main():
    await start_http()

    connector = TCPConnector(limit=10, ttl_dns_cache=300)
    async with ClientSession(connector=connector) as session:
        await poll_discord(session)

if __name__ == "__main__":
    asyncio.run(main())
