"""
Brainrot Auto-Join Relay Server (ENCRYPTED)
Connects to Discord, watches for brainrot detections, serves encrypted data over HTTP.
Deploy on Render.com (free forever).

Security:
  - API_KEY required on every request (header or query param)
  - Job IDs (server_id) are XOR-encrypted with ENCRYPTION_KEY + per-detection nonce
  - Join URLs are stripped (only encrypted server_id is sent)
"""

import discord
import os
import re
import time
import asyncio
import base64
import hashlib
import secrets
from aiohttp import web

# ─── CONFIG (set these as Environment Variables on Render) ───
DISCORD_TOKEN  = os.environ["DISCORD_TOKEN"]
CHANNEL_ID     = int(os.environ["CHANNEL_ID"])
API_KEY        = os.environ["API_KEY"]            # random string, must match Luau script
ENCRYPTION_KEY = os.environ["ENCRYPTION_KEY"]      # random string, must match Luau script
PORT           = int(os.environ.get("PORT", 10000))

# ─── STORAGE ───
detections = []
detection_counter = 0
MAX_DETECTIONS = 50
start_time = time.time()

# ─── ENCRYPTION ───

def derive_key(nonce_bytes):
    """Derive a per-message key from the master key + nonce using HMAC-SHA256."""
    return hashlib.sha256(ENCRYPTION_KEY.encode() + nonce_bytes).digest()

def encrypt_string(plaintext):
    """
    Encrypt a string using XOR with a derived key.
    Returns: base64(nonce + ciphertext)
    - nonce is 16 random bytes (unique per encryption)
    - ciphertext is XOR of plaintext bytes with derived key bytes (cycling)
    """
    if not plaintext:
        return ""
    nonce = secrets.token_bytes(16)
    key = derive_key(nonce)
    plain_bytes = plaintext.encode("utf-8")
    cipher_bytes = bytes([b ^ key[i % len(key)] for i, b in enumerate(plain_bytes)])
    return base64.b64encode(nonce + cipher_bytes).decode("ascii")


# ─── AUTH MIDDLEWARE ───

def check_api_key(request):
    """Check API key from header or query param."""
    key = request.headers.get("X-API-Key") or request.query.get("key")
    return key == API_KEY


# ─── DISCORD BOT ───
intents = discord.Intents.default()
intents.message_content = True
client = discord.Client(intents=intents)


def parse_roblox_url(url):
    """Extract placeId and serverId from a Roblox join URL."""
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
        launch_data = m.group(1)
        m2 = re.search(r'serverJobId:([a-f0-9-]+)', launch_data)
        if m2:
            server_id = m2.group(1)

    return place_id, server_id


def parse_message(message):
    """Parse a Discord message for brainrot detection data."""
    global detection_counter
    results = []

    join_urls = []
    for row in message.components:
        for comp in row.children:
            if hasattr(comp, 'url') and comp.url:
                if 'roblox' in comp.url.lower():
                    join_urls.append(comp.url)

    for i, embed in enumerate(message.embeds):
        data = {
            "category": "unknown",
            "brainrot_name": "",
            "value": "",
            "server_id": "",        # will be encrypted before sending
            "place_id": "",
            "raw_server_id": "",    # kept in memory, never sent
            "raw_title": "",
            "raw_description": "",
            "timestamp": time.time(),
        }

        title = (embed.title or "") + " " + (getattr(embed.author, 'name', '') or "")
        data["raw_title"] = title.strip()
        data["raw_description"] = embed.description or ""

        tl = title.lower()
        if "ultralight" in tl:
            data["category"] = "ultralight"
        elif "midlight" in tl:
            data["category"] = "midlight"
        elif "highlight" in tl:
            data["category"] = "highlight"
        elif "100m" in tl or "\U0001f4b0" in title:
            data["category"] = "100m+"

        for field in embed.fields:
            nl = field.name.lower()
            if any(k in nl for k in ["brainrot", "name", "item", "pet"]):
                data["brainrot_name"] = field.value
            elif any(k in nl for k in ["value", "price", "worth", "rap", "cost"]):
                data["value"] = field.value
            elif any(k in nl for k in ["server", "link", "job", "id"]):
                if not data["raw_server_id"]:
                    data["raw_server_id"] = field.value

        if not data["brainrot_name"] and embed.description:
            data["brainrot_name"] = embed.description[:120]

        url = join_urls[i] if i < len(join_urls) else (join_urls[0] if join_urls else "")
        if url:
            pid, sid = parse_roblox_url(url)
            if pid:
                data["place_id"] = pid
            if sid and not data["raw_server_id"]:
                data["raw_server_id"] = sid

        # Encrypt the server_id for storage
        data["server_id"] = encrypt_string(data["raw_server_id"])

        detection_counter += 1
        data["id"] = detection_counter
        results.append(data)

    return results


@client.event
async def on_ready():
    print(f"[BOT] Connected as {client.user} | Watching channel {CHANNEL_ID}")


@client.event
async def on_message(message):
    if message.channel.id != CHANNEL_ID:
        return
    if not message.embeds:
        return

    results = parse_message(message)
    for d in results:
        detections.append(d)
        print(f"[DETECTION] #{d['id']} | {d['category']} | {d['brainrot_name']} | {d['value']}")

    while len(detections) > MAX_DETECTIONS:
        detections.pop(0)


# ─── HTTP SERVER (all endpoints require API key) ───

def sanitize_detection(d):
    """Remove raw_server_id before sending — only encrypted version leaves the server."""
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
    """Health check — no API key needed (Render uses this to keep alive)."""
    return web.json_response({
        "status": "ok",
        "bot_ready": client.is_ready(),
        "uptime_seconds": round(time.time() - start_time),
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
    print(f"[HTTP] Server running on port {PORT}")


# ─── MAIN ───

async def main():
    await start_http()
    await client.start(DISCORD_TOKEN)

if __name__ == "__main__":
    asyncio.run(main())
