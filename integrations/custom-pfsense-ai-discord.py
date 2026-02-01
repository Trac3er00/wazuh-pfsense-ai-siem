#!/usr/bin/env python3
"""
AI-Powered pfSense Security Alert Integration for Wazuh
Analyzes firewall blocks with LLM to identify real attacks vs noise
Only alerts on confirmed threats or when AI unavailable for unknown traffic

Author: @Trac3er00
"""

import sys
import json
import requests
import re
from datetime import datetime

# =============================================================================
# CONFIGURATION - Edit these values for your environment
# =============================================================================

DEBUG_LOG = "/tmp/pfsense-ai-debug.log"
LMSTUDIO_URL = "http://10.10.0.136:1234/v1/chat/completions"  # Your LMStudio server
LMSTUDIO_MODEL = "qwen/qwen3-14b"  # Model name
DISCORD_WEBHOOK = "YOUR_DISCORD_WEBHOOK_HERE"  # Replace with your webhook

N8N_BASE_URL = "https://n8n.yourserver.com/webhook"  # Your n8n server
N8N_QUARANTINE_WEBHOOK = f"{N8N_BASE_URL}/wazuh-quarantine"

# Categories that trigger alerts
ALERT_CATEGORIES = ["port_scan", "brute_force", "exploit", "malware", "c2", "reconnaissance"]
ALERT_THREAT_LEVELS = ["critical", "high"]

# =============================================================================
# SAFE PATTERNS - Skip analysis for these
# =============================================================================

# Known safe/internal IPs - never alert on these
SAFE_IP_PATTERNS = [
    r'^10\.10\.0\.',        # Internal LAN
    r'^10\.10\.1\.',        # Internal LAN
    r'^192\.168\.',         # Private networks
    r'^127\.',              # Localhost
    r'^224\.',              # Multicast
    r'^239\.',              # Multicast
    r'^ff0',                # IPv6 multicast
    r'^fe80:',              # IPv6 link-local
]

# Known noisy protocols/ports to skip
SKIP_PORTS = [
    137, 138, 139,  # NetBIOS
    445,            # SMB
    5353,           # mDNS
    1900,           # SSDP/UPnP
    67, 68,         # DHCP
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

def is_safe_ip(ip):
    """Check if IP matches safe patterns"""
    if not ip:
        return True
    for pattern in SAFE_IP_PATTERNS:
        if re.match(pattern, ip):
            return True
    return False

def is_noisy_port(port):
    """Check if port is known noisy port"""
    try:
        return int(port) in SKIP_PORTS
    except:
        return False

def parse_pfsense_log(full_log):
    """Extract useful info from pfSense filterlog"""
    info = {
        "src_ip": "Unknown",
        "dst_ip": "Unknown",
        "src_port": "Unknown",
        "dst_port": "Unknown",
        "protocol": "Unknown",
        "interface": "Unknown",
        "direction": "in"
    }
    
    # pfSense filterlog format varies, try to extract key fields
    parts = full_log.split(",")
    if len(parts) > 10:
        info["interface"] = parts[4] if len(parts) > 4 else "Unknown"
        info["direction"] = parts[7] if len(parts) > 7 else "in"
        
        # IPv4 format has src/dst at different positions
        if len(parts) > 18:
            info["src_ip"] = parts[15] if len(parts) > 15 else "Unknown"
            info["dst_ip"] = parts[16] if len(parts) > 16 else "Unknown"
            info["protocol"] = parts[12] if len(parts) > 12 else "Unknown"
            
            # TCP/UDP have ports
            if info["protocol"] in ["tcp", "TCP", "udp", "UDP"] and len(parts) > 20:
                info["src_port"] = parts[17] if len(parts) > 17 else "Unknown"
                info["dst_port"] = parts[18] if len(parts) > 18 else "Unknown"
    
    return info

def analyze_with_ai(log_info, full_log):
    """Send connection info to AI for analysis"""
    prompt = f"""Cybersecurity analyst: Analyze this blocked firewall connection.

Source IP: {log_info['src_ip']}
Destination IP: {log_info['dst_ip']}
Source Port: {log_info['src_port']}
Destination Port: {log_info['dst_port']}
Protocol: {log_info['protocol']}
Interface: {log_info['interface']}
Direction: {log_info['direction']}

Raw log: {full_log[:500]}

CONTEXT: This connection was BLOCKED by pfSense firewall.

Most blocked traffic is routine (broadcast, discovery, misconfiguration).
Only flag as threat if there's HIGH CONFIDENCE of malicious activity.

Categories:
- "port_scan" = scanning multiple ports
- "brute_force" = repeated connection attempts
- "exploit" = known exploit attempt
- "malware" = malware communication
- "c2" = command and control
- "reconnaissance" = network probing
- "noise" = routine traffic (multicast, broadcast, discovery)
- "misconfiguration" = likely config issue
- "safe" = benign traffic

JSON response only:
{{"threat_level":"critical|high|medium|low|info","category":"category","recommendation":"action","explanation":"reason","needs_attention":true/false,"quarantine_source":true/false}}"""

    try:
        response = requests.post(LMSTUDIO_URL, json={
            "model": LMSTUDIO_MODEL,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.1, "max_tokens": 300
        }, timeout=30)
        
        if response.status_code == 200:
            content = response.json()["choices"][0]["message"]["content"]
            start, end = content.find('{'), content.rfind('}') + 1
            if start != -1 and end > start:
                result = json.loads(content[start:end])
                for key in ["needs_attention", "quarantine_source"]:
                    if isinstance(result.get(key), str):
                        result[key] = result[key].lower() == "true"
                result["ai_available"] = True
                return result
    except Exception as e:
        debug_log(f"AI error: {e}")
    
    return {
        "threat_level": "medium",
        "category": "unknown",
        "recommendation": "Manual review - AI unavailable",
        "explanation": "AI unreachable",
        "needs_attention": True,
        "quarantine_source": False,
        "ai_available": False
    }

def send_to_discord(alert_data, log_info, ai_analysis):
    """Send alert to Discord"""
    level = ai_analysis.get("threat_level", "medium")
    cat = ai_analysis.get("category", "unknown")
    ai_ok = ai_analysis.get("ai_available", True)
    src_ip = log_info.get("src_ip", "Unknown")
    
    colors = {"critical": 0xFF0000, "high": 0xFF6600, "medium": 0xFFFF00, "low": 0x00FF00, "info": 0x0099FF}
    emojis = {"critical": "🚨", "high": "⚠️", "medium": "🔶", "low": "🔵", "info": "ℹ️"}
    cat_emojis = {
        "port_scan": "🔍", "brute_force": "🔓", "exploit": "💥", 
        "malware": "🦠", "c2": "🎯", "reconnaissance": "👁️",
        "noise": "📢", "misconfiguration": "⚙️", "safe": "✅", "unknown": "❓"
    }
    
    import urllib.parse
    params = urllib.parse.urlencode({
        "ip": src_ip, "domain": f"firewall-block", 
        "category": cat, "threat": level
    })
    q_url = f"{N8N_QUARANTINE_WEBHOOK}?{params}"
    
    if ai_ok:
        title = f"{emojis.get(level, '❓')} pfSense Alert - {level.upper()}"
        color = colors.get(level, 0x808080)
    else:
        title = "🔮 pfSense Alert - MANUAL REVIEW"
        color = 0x9932CC
    
    embed = {
        "title": title,
        "color": color,
        "fields": [
            {"name": f"{cat_emojis.get(cat, '❓')} Category", "value": cat.capitalize(), "inline": True},
            {"name": "📊 Threat Level", "value": level.capitalize(), "inline": True},
            {"name": "🔥 Source IP", "value": f"`{src_ip}`", "inline": True},
            {"name": "🎯 Destination", "value": f"`{log_info.get('dst_ip', 'Unknown')}:{log_info.get('dst_port', '?')}`", "inline": True},
            {"name": "🔌 Protocol", "value": log_info.get('protocol', 'Unknown'), "inline": True},
            {"name": "🚪 Interface", "value": log_info.get('interface', 'Unknown'), "inline": True},
            {"name": "🤖 Analysis", "value": ai_analysis.get("explanation", "N/A")[:200], "inline": False},
            {"name": "💡 Recommendation", "value": ai_analysis.get("recommendation", "N/A"), "inline": False},
        ],
        "footer": {"text": "Wazuh • pfSense AI Analysis"},
        "timestamp": alert_data.get("timestamp", datetime.now().isoformat())
    }
    
    if src_ip and src_ip != "Unknown" and not is_safe_ip(src_ip):
        embed["fields"].append({
            "name": "⚡ Quick Actions",
            "value": f"🔒 [Quarantine {src_ip}]({q_url})",
            "inline": False
        })
    
    try:
        requests.post(DISCORD_WEBHOOK, json={
            "username": "Wazuh pfSense AI",
            "embeds": [embed]
        }, timeout=10)
        debug_log(f"Discord sent for {src_ip}")
    except Exception as e:
        debug_log(f"Discord error: {e}")

# =============================================================================
# MAIN
# =============================================================================

def main():
    debug_log(f"=== pfSense AI script called: {sys.argv}")
    
    alert_file = next((a for a in sys.argv[1:] if '/tmp/' in a and '.alert' in a), None)
    if not alert_file:
        debug_log("No alert file")
        sys.exit(0)
    
    alert_data = read_alert_file(alert_file)
    if not alert_data:
        sys.exit(0)
    
    full_log = alert_data.get("full_log", "")
    if not full_log:
        debug_log("No log data")
        sys.exit(0)
    
    # Parse the pfSense log
    log_info = parse_pfsense_log(full_log)
    
    # Also check data field for srcip (Wazuh may extract it)
    data = alert_data.get("data", {})
    if data.get("srcip"):
        log_info["src_ip"] = data["srcip"]
    if data.get("dstip"):
        log_info["dst_ip"] = data["dstip"]
    if data.get("dstport"):
        log_info["dst_port"] = data["dstport"]
    if data.get("protocol"):
        log_info["protocol"] = data["protocol"]
    
    debug_log(f"Parsed: {log_info}")
    
    # Skip safe internal IPs
    if is_safe_ip(log_info["src_ip"]):
        debug_log(f"Safe source IP: {log_info['src_ip']}")
        sys.exit(0)
    
    # Skip noisy ports
    if is_noisy_port(log_info.get("dst_port")):
        debug_log(f"Noisy port: {log_info['dst_port']}")
        sys.exit(0)
    
    debug_log(f"Analyzing: {log_info['src_ip']} -> {log_info['dst_ip']}:{log_info['dst_port']}")
    
    # AI analysis
    ai = analyze_with_ai(log_info, full_log)
    debug_log(f"AI: {ai}")
    
    # If AI unavailable and external IP, alert for manual review
    if not ai.get("ai_available", True):
        debug_log(f"AI down - manual review for {log_info['src_ip']}")
        send_to_discord(alert_data, log_info, ai)
        sys.exit(0)
    
    # AI available - only alert on real threats
    cat = ai.get("category", "").lower()
    level = ai.get("threat_level", "").lower()
    
    if cat not in ALERT_CATEGORIES:
        debug_log(f"Safe category: {cat}")
        sys.exit(0)
    
    if level not in ALERT_THREAT_LEVELS:
        debug_log(f"Low threat: {level}")
        sys.exit(0)
    
    debug_log(f"ALERT: {log_info['src_ip']} - {cat}/{level}")
    send_to_discord(alert_data, log_info, ai)
    sys.exit(0)

if __name__ == "__main__":
    main()
