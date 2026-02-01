#!/usr/bin/env python3
"""
AI-Powered DNS Security Alert Integration for Wazuh
Analyzes DNS queries with LLM to detect malicious domains
Only alerts on unblocked domains that AI classifies as threats

Author: @Trac3er00
"""

import sys
import json
import requests
import re
import urllib.parse
from datetime import datetime

# =============================================================================
# CONFIGURATION - Edit these values for your environment
# =============================================================================

DEBUG_LOG = "/tmp/ai-dns-debug.log"
LMSTUDIO_URL = "http://10.10.0.136:1234/v1/chat/completions"  # Your LMStudio server
LMSTUDIO_MODEL = "qwen/qwen3-14b"  # Model name
DISCORD_WEBHOOK = "YOUR_DISCORD_WEBHOOK_HERE"  # Replace with your webhook

N8N_BASE_URL = "https://n8n.yourserver.com/webhook"  # Your n8n server
N8N_QUARANTINE_WEBHOOK = f"{N8N_BASE_URL}/wazuh-quarantine"
N8N_IGNORE_WEBHOOK = f"{N8N_BASE_URL}/wazuh-ignore"

IGNORED_DOMAINS_FILE = "/var/ossec/etc/lists/ignored-domains.txt"

# Categories that trigger alerts
ALERT_CATEGORIES = ["malware", "phishing", "c2", "cryptominer", "suspicious"]
ALERT_THREAT_LEVELS = ["critical", "high"]

# =============================================================================
# SAFE DOMAIN PATTERNS - Domains matching these won't trigger AI analysis
# =============================================================================

KNOWN_SAFE_PATTERNS = [
    # Amazon
    r'\.a2z\.com$', r'\.amazon\.dev$', r'\.amazon\.com$', r'\.amazonaws\.com$',
    r'advertising\.amazon', r'device-metrics.*\.amazon', r'\.primevideo\.com$',
    r'fls-na\.amazon', r'unagi.*\.amazon', r'arcus-uswest\.amazon',
    r'\.media-amazon\.com$', r'\.ssl-images-amazon\.com$',
    
    # Apple
    r'\.apple\.com$', r'\.icloud\.com$', r'\.apple-dns\.net$', r'\.mzstatic\.com$',
    r'\.itunes\.com$', r'iadsdk\.apple', r'idiagnostics\.apple', r'xp\.apple\.com',
    
    # Google
    r'\.google\.com$', r'\.googleapis\.com$', r'\.gstatic\.com$', r'\.youtube\.com$',
    r'\.googlevideo\.com$', r'\.doubleclick\.net$', r'\.google-analytics\.com$',
    r'\.googleadservices\.com$', r'\.googlesyndication\.com$', r'\.gvt[0-9]\.com$',
    r'\.app-measurement\.com$', r'\.crashlytics\.com$', r'\.firebase\.com$',
    r'\.firebaseio\.com$', r'google\.com$', r'www\.google\.com$',
    
    # Microsoft
    r'\.microsoft\.com$', r'\.msftconnecttest\.com$', r'\.windows\.com$',
    r'\.windowsupdate\.com$', r'\.office\.com$', r'\.office365\.com$',
    r'\.live\.com$', r'\.bing\.com$', r'\.msn\.com$', r'\.azure\.com$',
    r'\.msedge\.net$', r'\.skype\.com$', r'\.linkedin\.com$',
    
    # Meta/Facebook
    r'\.facebook\.com$', r'\.fbcdn\.net$', r'\.instagram\.com$', r'\.whatsapp\.com$',
    r'\.meta\.com$', r'\.fb\.com$', r'\.messenger\.com$',
    
    # CDN & Infrastructure
    r'\.cloudflare\.com$', r'\.cloudflare-dns\.com$', r'\.akamai\.net$',
    r'\.akamaiedge\.net$', r'\.fastly\.net$', r'\.edgekey\.net$',
    r'\.edgesuite\.net$', r'\.cloudfront\.net$', r'\.azureedge\.net$',
    
    # Analytics & Telemetry (safe but tracked)
    r'\.anthropic\.com$', r'\.openai\.com$', r'\.statsig\.com$',
    r'\.braze\.com$', r'\.branch\.io$', r'\.segment\.com$', r'\.mixpanel\.com$',
    r'\.amplitude\.com$', r'\.appsflyer\.com$', r'\.adjust\.com$',
    r'\.sentry\.io$', r'\.bugsnag\.com$', r'\.instabug\.com$',
    
    # Streaming & Entertainment
    r'\.netflix\.com$', r'\.nflxvideo\.net$', r'\.spotify\.com$',
    r'\.scdn\.co$', r'\.hulu\.com$', r'\.disneyplus\.com$',
    r'\.twitch\.tv$', r'\.ttvnw\.net$',
    
    # Korean Services
    r'\.daum\.net$', r'\.kakao\.com$', r'\.naver\.com$', r'\.naver\.net$',
    r'\.pstatic\.net$', r'\.kakaocorp\.com$',
    
    # Development & APIs
    r'\.github\.com$', r'\.githubusercontent\.com$', r'\.npmjs\.com$',
    r'\.pypi\.org$', r'\.docker\.com$', r'\.docker\.io$',
    
    # Generic patterns (be careful with these)
    r'^analytics\.', r'^telemetry\.', r'^metrics\.', r'^tracking\.',
    r'^logs\.', r'^stats\.', r'^api\.', r'adserver', r'adservice',
    r'doubleclick', r'googlesyndication', r'googleads',
]

# =============================================================================
# FUNCTIONS
# =============================================================================

def debug_log(msg):
    """Write debug message to log file"""
    try:
        with open(DEBUG_LOG, "a") as f:
            f.write(f"{datetime.now()}: {msg}\n")
    except:
        pass

def read_alert_file(alert_file):
    """Read and parse the Wazuh alert JSON file"""
    try:
        with open(alert_file, 'r') as f:
            return json.load(f)
    except Exception as e:
        debug_log(f"Error reading alert file: {e}")
        return None

def is_domain_ignored(domain):
    """Check if domain is in user's ignore list"""
    try:
        with open(IGNORED_DOMAINS_FILE, 'r') as f:
            ignored = [line.strip().lower() for line in f if line.strip()]
            return domain.lower() in ignored
    except FileNotFoundError:
        return False
    except Exception as e:
        debug_log(f"Error reading ignored domains: {e}")
        return False

def matches_safe_pattern(domain):
    """Check if domain matches known safe patterns"""
    domain_lower = domain.lower()
    for pattern in KNOWN_SAFE_PATTERNS:
        if re.search(pattern, domain_lower):
            return True
    return False

def analyze_with_ai(domain, client_ip):
    """Send domain to LMStudio for AI analysis"""
    prompt = f"""Cybersecurity analyst: Classify this DNS query.

Domain: {domain}
Client IP: {client_ip}

Categories (pick one):
- "malware" = known malware/C2 domain
- "phishing" = credential theft/fake site
- "c2" = command and control server
- "cryptominer" = cryptocurrency mining
- "suspicious" = DGA pattern or highly suspicious
- "tracking" = advertising/analytics/telemetry
- "safe" = legitimate service
- "unknown" = cannot determine

Threat levels: critical, high, medium, low, info

Respond ONLY with JSON:
{{"category":"category","threat_level":"level","confidence":"high/medium/low","reason":"brief explanation"}}"""

    try:
        response = requests.post(
            LMSTUDIO_URL,
            json={
                "model": LMSTUDIO_MODEL,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.1,
                "max_tokens": 200
            },
            timeout=30
        )
        
        if response.status_code == 200:
            content = response.json()["choices"][0]["message"]["content"]
            # Extract JSON from response
            start = content.find('{')
            end = content.rfind('}') + 1
            if start != -1 and end > start:
                result = json.loads(content[start:end])
                result["ai_available"] = True
                return result
    except Exception as e:
        debug_log(f"AI error: {e}")
    
    # AI unavailable - return unknown
    return {
        "category": "unknown",
        "threat_level": "medium",
        "confidence": "low",
        "reason": "AI analysis unavailable",
        "ai_available": False
    }

def send_to_discord(domain, client_ip, ai_result, alert_data):
    """Send alert to Discord with action buttons"""
    category = ai_result.get("category", "unknown")
    threat_level = ai_result.get("threat_level", "unknown")
    reason = ai_result.get("reason", "No details")
    ai_available = ai_result.get("ai_available", True)
    
    # Colors and emojis
    colors = {
        "critical": 0xFF0000, "high": 0xFF6600, "medium": 0xFFFF00,
        "low": 0x00FF00, "info": 0x0099FF
    }
    emojis = {
        "malware": "🦠", "phishing": "🎣", "c2": "🎯",
        "cryptominer": "⛏️", "suspicious": "⚠️", "tracking": "📊",
        "safe": "✅", "unknown": "❓"
    }
    
    color = colors.get(threat_level, 0xFF6600)
    emoji = emojis.get(category, "❓")
    
    # Build action URLs
    q_params = urllib.parse.urlencode({
        "ip": client_ip, "domain": domain,
        "category": category, "threat": threat_level
    })
    i_params = urllib.parse.urlencode({
        "domain": domain, "clientip": client_ip, "category": category
    })
    quarantine_url = f"{N8N_QUARANTINE_WEBHOOK}?{q_params}"
    ignore_url = f"{N8N_IGNORE_WEBHOOK}?{i_params}"
    
    # Build title
    if ai_available:
        title = f"🚨 DNS Alert - {category.upper()} ({threat_level})"
    else:
        title = f"🔮 DNS Alert - MANUAL REVIEW NEEDED"
    
    embed = {
        "title": title,
        "color": color,
        "fields": [
            {"name": f"{emoji} Domain", "value": f"`{domain}`", "inline": False},
            {"name": "📊 Category", "value": category.capitalize(), "inline": True},
            {"name": "⚡ Threat Level", "value": threat_level.capitalize(), "inline": True},
            {"name": "🖥️ Client IP", "value": f"`{client_ip}`", "inline": True},
            {"name": "🤖 AI Analysis", "value": reason, "inline": False},
            {"name": "⚡ Quick Actions", "value": f"🔒 [Quarantine {client_ip}]({quarantine_url})\n🚫 [Ignore Domain]({ignore_url})", "inline": False}
        ],
        "footer": {"text": "Wazuh • AI DNS Analysis"},
        "timestamp": alert_data.get("timestamp", datetime.now().isoformat())
    }
    
    payload = {
        "username": "Wazuh DNS Monitor",
        "embeds": [embed]
    }
    
    try:
        response = requests.post(DISCORD_WEBHOOK, json=payload, timeout=10)
        debug_log(f"Discord sent: {response.status_code}")
    except Exception as e:
        debug_log(f"Discord error: {e}")

# =============================================================================
# MAIN
# =============================================================================

def main():
    debug_log(f"=== Script called: {sys.argv}")
    
    # Find alert file in arguments
    alert_file = next((a for a in sys.argv[1:] if '/tmp/' in a and '.alert' in a), None)
    if not alert_file:
        debug_log("No alert file found in arguments")
        sys.exit(0)
    
    # Read alert data
    alert_data = read_alert_file(alert_file)
    if not alert_data:
        sys.exit(0)
    
    # Extract DNS query info
    data = alert_data.get("data", {})
    domain = data.get("QH", "")
    client_ip = data.get("IP", "Unknown")
    is_filtered = str(data.get("IsFiltered", "")).lower() == "true"
    
    if not domain:
        debug_log("No domain in alert")
        sys.exit(0)
    
    debug_log(f"Processing: {domain} from {client_ip} (filtered={is_filtered})")
    
    # SKIP if already blocked by AdGuard
    if is_filtered:
        debug_log(f"SKIP: Already blocked by AdGuard")
        sys.exit(0)
    
    # SKIP if matches safe patterns
    if matches_safe_pattern(domain):
        debug_log(f"SKIP: Matches safe pattern")
        sys.exit(0)
    
    # SKIP if in user ignore list
    if is_domain_ignored(domain):
        debug_log(f"SKIP: User ignored domain")
        sys.exit(0)
    
    # Analyze with AI
    debug_log(f"Analyzing with AI: {domain}")
    ai_result = analyze_with_ai(domain, client_ip)
    debug_log(f"AI result: {ai_result}")
    
    # Check if we should alert
    category = ai_result.get("category", "").lower()
    threat_level = ai_result.get("threat_level", "").lower()
    ai_available = ai_result.get("ai_available", True)
    
    # If AI unavailable for truly unknown domain, alert for manual review
    if not ai_available and category == "unknown":
        debug_log(f"ALERT: AI unavailable for unknown domain")
        send_to_discord(domain, client_ip, ai_result, alert_data)
        sys.exit(0)
    
    # If AI classified as safe/tracking, skip
    if category not in ALERT_CATEGORIES:
        debug_log(f"SKIP: Category {category} not in alert list")
        sys.exit(0)
    
    # If threat level too low, skip
    if threat_level not in ALERT_THREAT_LEVELS:
        debug_log(f"SKIP: Threat level {threat_level} too low")
        sys.exit(0)
    
    # Send alert
    debug_log(f"ALERT: {domain} - {category}/{threat_level}")
    send_to_discord(domain, client_ip, ai_result, alert_data)
    sys.exit(0)

if __name__ == "__main__":
    main()
