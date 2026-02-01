#!/usr/bin/env python3
"""
SSH Security Alert Integration for Wazuh
Alerts on brute force, failed logins, and suspicious SSH activity

Author: @Trac3er00
"""

import sys
import json
import requests
import urllib.parse
from datetime import datetime

# =============================================================================
# CONFIGURATION - Edit these values for your environment
# =============================================================================

DEBUG_LOG = "/tmp/ssh-discord-debug.log"
DISCORD_WEBHOOK = "YOUR_DISCORD_WEBHOOK_HERE"  # Replace with your webhook

N8N_BASE_URL = "https://n8n.yourserver.com/webhook"  # Your n8n server
N8N_QUARANTINE_WEBHOOK = f"{N8N_BASE_URL}/wazuh-quarantine"

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

def get_alert_info(alert_data):
    """Extract relevant information from alert"""
    rule = alert_data.get("rule", {})
    data = alert_data.get("data", {})
    
    # Try to extract source IP from various fields
    srcip = data.get("srcip") or alert_data.get("srcip") or "Unknown"
    srcuser = data.get("srcuser") or data.get("dstuser") or "Unknown"
    
    return {
        "rule_id": rule.get("id", "Unknown"),
        "level": rule.get("level", 0),
        "description": rule.get("description", "Unknown"),
        "groups": rule.get("groups", []),
        "full_log": alert_data.get("full_log", ""),
        "srcip": srcip,
        "srcuser": srcuser,
        "timestamp": alert_data.get("timestamp", datetime.now().isoformat()),
        "agent": alert_data.get("agent", {}).get("name", "Unknown"),
        "location": alert_data.get("location", "Unknown")
    }

def send_to_discord(alert_info):
    """Send alert to Discord with action buttons"""
    level = alert_info["level"]
    srcip = alert_info["srcip"]
    
    # Color based on level
    if level >= 10:
        color, emoji = 0xFF0000, "🚨"
        severity = "CRITICAL"
    elif level >= 7:
        color, emoji = 0xFF6600, "⚠️"
        severity = "HIGH"
    elif level >= 5:
        color, emoji = 0xFFFF00, "🔶"
        severity = "MEDIUM"
    else:
        color, emoji = 0x00AAFF, "🔵"
        severity = "LOW"
    
    # Build quarantine URL
    action_text = ""
    if srcip and srcip != "Unknown":
        params = urllib.parse.urlencode({
            "ip": srcip,
            "domain": "SSH-alert",
            "category": "ssh_brute_force",
            "threat": f"level-{level}"
        })
        q_url = f"{N8N_QUARANTINE_WEBHOOK}?{params}"
        action_text = f"🔒 [Quarantine {srcip}]({q_url})"
    
    embed = {
        "title": f"{emoji} SSH Security Alert - {severity}",
        "color": color,
        "fields": [
            {"name": "🔐 Event", "value": alert_info["description"], "inline": False},
            {"name": "🖥️ Source IP", "value": f"`{srcip}`", "inline": True},
            {"name": "👤 User", "value": f"`{alert_info['srcuser']}`", "inline": True},
            {"name": "📊 Level", "value": str(level), "inline": True},
            {"name": "🎯 Target", "value": alert_info["agent"], "inline": True},
            {"name": "📝 Log", "value": f"```{alert_info['full_log'][:400]}```", "inline": False},
        ],
        "footer": {"text": f"Wazuh • Rule {alert_info['rule_id']}"},
        "timestamp": alert_info["timestamp"]
    }
    
    if action_text:
        embed["fields"].append({"name": "⚡ Quick Actions", "value": action_text, "inline": False})
    
    payload = {
        "username": "Wazuh SSH Monitor",
        "embeds": [embed]
    }
    
    try:
        resp = requests.post(DISCORD_WEBHOOK, json=payload, timeout=10)
        debug_log(f"Discord response: {resp.status_code}")
    except Exception as e:
        debug_log(f"Discord error: {e}")

# =============================================================================
# MAIN
# =============================================================================

def main():
    debug_log(f"=== SSH script called: {sys.argv}")
    
    alert_file = next((a for a in sys.argv[1:] if '/tmp/' in a and '.alert' in a), None)
    if not alert_file:
        debug_log("No alert file")
        sys.exit(0)
    
    alert_data = read_alert_file(alert_file)
    if not alert_data:
        sys.exit(0)
    
    alert_info = get_alert_info(alert_data)
    debug_log(f"Alert: {alert_info['description']} (level {alert_info['level']})")
    
    send_to_discord(alert_info)
    debug_log("Alert sent to Discord")
    sys.exit(0)

if __name__ == "__main__":
    main()
