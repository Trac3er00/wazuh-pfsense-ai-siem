# 🛡️ Wazuh AI-Powered SIEM Stack

A comprehensive Security Information and Event Management (SIEM) solution combining **Wazuh** with **AI-powered threat analysis**, **automated response actions**, and **natural language log querying**.

![Wazuh](https://img.shields.io/badge/Wazuh-4.14.2-blue)
![Python](https://img.shields.io/badge/Python-3.10+-green)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

## 🌟 Features

- **AI-Powered Threat Analysis** - Uses local LLM (LMStudio/Ollama) to analyze DNS queries, firewall blocks, and security events
- **Natural Language Log Search** - Query your security logs with plain English ("Were there any SSH attacks today?")
- **Multi-Source Monitoring** - AdGuard DNS, pfSense firewall, SSH authentication
- **Discord Alerts** - Real-time security notifications with one-click response actions
- **Automated Response** - Quarantine devices via pfSense firewall with n8n workflows
- **Custom Dashboard** - Pre-configured Wazuh visualizations for security overview
- **Noise Reduction** - Smart filtering to only alert on real threats

## 📐 Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           WAZUH SERVER (10.10.0.27)                     │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐    │
│  │   Wazuh     │  │   Threat    │  │    MCP      │  │   Discord   │    │
│  │   Manager   │  │   Hunter    │  │   Server    │  │   Alerts    │    │
│  │   :55000    │  │   :8080     │  │   :8081     │  │             │    │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘    │
│         │                │                │                │           │
│         └────────────────┴────────────────┴────────────────┘           │
│                                   │                                     │
└───────────────────────────────────┼─────────────────────────────────────┘
                                    │
        ┌───────────────────────────┼───────────────────────────┐
        │                           │                           │
        ▼                           ▼                           ▼
┌───────────────┐          ┌───────────────┐          ┌───────────────┐
│   AdGuard     │          │   pfSense     │          │   LMStudio    │
│   DNS Agent   │          │   Firewall    │          │   AI Server   │
│  10.10.0.35   │          │  10.10.0.1    │          │  10.10.0.136  │
│   (Agent)     │          │   (Syslog)    │          │   (Qwen 14B)  │
└───────────────┘          └───────────────┘          └───────────────┘
                                    │
                                    ▼
                           ┌───────────────┐
                           │     n8n       │
                           │  Automation   │
                           │  (Webhooks)   │
                           └───────────────┘
```

## 🚀 Quick Start

### Prerequisites

- Ubuntu 24.04 server (6+ cores, 16GB+ RAM recommended)
- Wazuh 4.14+ installed
- pfSense firewall with SSH access
- AdGuard Home DNS server
- LMStudio or Ollama for AI inference
- n8n for workflow automation
- Discord webhook for alerts

### Installation

```bash
# Clone the repository
git clone https://github.com/Trac3er00/wazuh-ai-siem.git
cd wazuh-ai-siem

# Run the setup script
chmod +x scripts/setup.sh
sudo ./scripts/setup.sh
```

## 📁 Repository Structure

```
wazuh-ai-siem/
├── README.md                          # This file
├── docs/
│   ├── SETUP.md                       # Detailed setup guide
│   ├── CONFIGURATION.md               # Configuration reference
│   └── TROUBLESHOOTING.md             # Common issues and fixes
├── integrations/
│   ├── custom-ai-dns-discord.py       # AI-powered DNS analysis
│   ├── custom-pfsense-ai-discord.py   # AI-powered firewall analysis
│   └── custom-ssh-discord.py          # SSH alert integration
├── rules/
│   ├── local_rules.xml                # Noise reduction rules
│   ├── pfsense_custom_rules.xml       # pfSense detection rules
│   └── local_adguard_rules.xml        # AdGuard DNS rules
├── decoders/
│   └── adguard_decoder.xml            # AdGuard log decoder
├── scripts/
│   ├── setup.sh                       # Main setup script
│   ├── pfsense-quarantine.sh          # pfSense quarantine script
│   └── test-integrations.sh           # Integration test script
├── services/
│   ├── threat_hunter.py               # AI Threat Hunter service
│   ├── mcp_server.py                  # MCP/Chat API server
│   ├── wazuh-threat-hunter.service    # Systemd service
│   └── wazuh-mcp.service              # Systemd service
├── n8n-workflows/
│   ├── wazuh-quarantine-workflow.json # Quarantine device workflow
│   ├── wazuh-unquarantine-workflow.json # Release device workflow
│   └── wazuh-ignore-workflow.json     # Ignore domain workflow
└── config/
    └── ossec.conf.example             # Example Wazuh configuration
```

## 🔧 Components

### 1. AI-Powered DNS Integration

Analyzes DNS queries with AI to detect malicious domains.

**Features:**
- Skips already-blocked domains (no duplicate alerts)
- Extensive safe pattern list (Amazon, Google, Apple, etc.)
- User-configurable ignore list
- Only alerts on critical/high threats

**File:** `integrations/custom-ai-dns-discord.py`

### 2. AI-Powered pfSense Integration

Analyzes firewall blocks to identify real attacks vs noise.

**Features:**
- Triggered on 20+ blocks from same IP in 1 minute
- AI classifies attack type (port scan, brute force, etc.)
- Fallback alerts when AI unavailable
- Quarantine button in Discord

**File:** `integrations/custom-pfsense-ai-discord.py`

### 3. SSH Monitoring

Detects SSH brute force attacks and suspicious logins.

**Features:**
- Alerts on 5+ failed attempts (brute force)
- Shows source IP, username, target
- One-click quarantine

**File:** `integrations/custom-ssh-discord.py`

### 4. AI Threat Hunter

Natural language security log search powered by LLM + vector database.

**Features:**
- Query logs with plain English
- FAISS vector store for semantic search
- REST API at port 8080

**Example queries:**
- "Were there any SSH brute force attacks?"
- "Show me blocked DNS queries from yesterday"
- "What IPs triggered the most alerts?"

**File:** `services/threat_hunter.py`

### 5. MCP Server / Chat API

REST API and web interface for SIEM interaction.

**Features:**
- List agents, alerts, summaries
- Natural language chat endpoint
- Web UI at `/ui`

**File:** `services/mcp_server.py`

### 6. n8n Automation Workflows

Automated response actions triggered from Discord.

| Workflow | Webhook | Action |
|----------|---------|--------|
| Quarantine | `/wazuh-quarantine` | Block IP on pfSense |
| Unquarantine | `/wazuh-unquarantine` | Release IP |
| Ignore Domain | `/wazuh-ignore` | Add to safe list |

## 📊 Dashboard

Custom Wazuh dashboard visualizations:

| Visualization | Type | Description |
|---------------|------|-------------|
| Alerts Over Time | Line | Timeline of all alert types |
| Alerts by Category | Pie | Breakdown by source (DNS, SSH, pfSense) |
| Alert Severity | Pie | Distribution by rule level |
| Top Source IPs | Bar | Most active IPs |
| Top Triggered Rules | Table | Most common alerts |

## 🔐 Noise Reduction

Built-in rules to suppress routine events:

| Event Type | Action |
|------------|--------|
| pfSense single blocks | Suppressed |
| AdGuard blocked queries | Suppressed |
| PAM session open/close | Suppressed |
| Sudo by trusted users | Suppressed |
| SSH from internal IPs | Suppressed |
| SSH brute force | **Alerts at level 10** |
| pfSense attacks (20+ blocks) | **Alerts at level 8+** |

## 🌐 Endpoints

| Service | Port | URL | Purpose |
|---------|------|-----|---------|
| Wazuh Dashboard | 443 | https://wazuh.local | Main SIEM UI |
| Wazuh API | 55000 | https://wazuh.local:55000 | Wazuh REST API |
| Threat Hunter | 8080 | http://wazuh.local:8080 | AI log search API |
| MCP Server | 8081 | http://wazuh.local:8081 | Chat API |
| Chat UI | 8081 | http://wazuh.local:8081/ui | Web chat interface |

## 🔄 Alert Flow

### DNS Alert Flow
```
DNS Query → AdGuard
  ├── Blocked (IsFiltered=true)? → Skip (no alert)
  └── Not blocked?
        ├── Known safe pattern? → Skip
        ├── User-ignored? → Skip
        └── Unknown → AI Analysis
              ├── Safe/tracking? → Skip
              └── Malicious? → Discord Alert
                    ├── [Quarantine] → Block IP
                    └── [Ignore] → Add to safe list
```

### pfSense Alert Flow
```
pfSense Event → Wazuh Rules
  ├── Level < 8? → Skip
  └── Level 8+ (attack detected)?
        → AI Analysis → Discord Alert
              └── [Quarantine] → Block IP
```

### SSH Alert Flow
```
SSH Event → Wazuh Rules
  ├── Single failure (level 4)? → Log only
  └── Brute force (level 10)?
        → Discord Alert
              └── [Quarantine] → Block IP
```

## ⚙️ Configuration

### Environment Variables

Create `/etc/wazuh-ai-siem.env`:

```bash
# LMStudio/Ollama
LMSTUDIO_URL=http://10.10.0.136:1234/v1/chat/completions
LMSTUDIO_MODEL=qwen/qwen3-14b

# Discord
DISCORD_WEBHOOK=https://discord.com/api/webhooks/YOUR_WEBHOOK_HERE

# n8n
N8N_BASE_URL=https://n8n.yourserver.com/webhook

# pfSense
PFSENSE_HOST=10.10.0.1
PFSENSE_SSH_PORT=2020
PFSENSE_SSH_KEY=/etc/ssh/pfsense_automation

# Wazuh API
WAZUH_API_USER=wazuh-wui
WAZUH_API_PASS=your_api_password
```

### Protected IPs

Edit `scripts/pfsense-quarantine.sh` to add IPs that should never be quarantined:

```bash
PROTECTED_IPS=("10.10.0.1" "10.10.0.27" "10.10.0.35" "10.10.0.167" "127.0.0.1")
```

### Safe Domain Patterns

Edit the `KNOWN_SAFE_PATTERNS` in `integrations/custom-ai-dns-discord.py` or add domains to:

```
/var/ossec/etc/lists/ignored-domains.txt
```

## 🧪 Testing

### Test DNS Integration
```bash
# Trigger a test alert
sudo python3 /var/ossec/integrations/custom-ai-dns-discord.py /tmp/test.alert
cat /tmp/ai-dns-debug.log
```

### Test pfSense Integration
```bash
# Create test alert
cat > /tmp/test-pfsense.alert << 'EOF'
{
  "timestamp": "2026-02-01T18:40:00.000+0000",
  "rule": {"level": 11, "id": "112011"},
  "data": {"srcip": "185.220.101.45", "dstip": "10.10.0.27", "dstport": "22"}
}
EOF

sudo python3 /var/ossec/integrations/custom-pfsense-ai-discord.py /tmp/test-pfsense.alert
```

### Test SSH Brute Force Detection
```bash
# From another machine, try 6 failed logins
ssh fakeuser@wazuh-server
# Enter wrong password 6 times
```

### Test Threat Hunter
```bash
curl -X POST http://localhost:8080/query \
  -H "Content-Type: application/json" \
  -d '{"question": "Were there any SSH attacks?", "hours": 24}'
```

### Test MCP Server
```bash
curl http://localhost:8081/agents
curl http://localhost:8081/alerts/summary
```

## 📝 Logs & Debugging

| Log | Location |
|-----|----------|
| DNS Integration | `/tmp/ai-dns-debug.log` |
| pfSense Integration | `/tmp/pfsense-ai-debug.log` |
| SSH Integration | `/tmp/ssh-discord-debug.log` |
| Threat Hunter | `journalctl -u wazuh-threat-hunter` |
| MCP Server | `journalctl -u wazuh-mcp` |
| Wazuh Alerts | `/var/ossec/logs/alerts/alerts.log` |
| Wazuh Archives | `/var/ossec/logs/archives/archives.json` |

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [Wazuh](https://wazuh.com/) - Open source SIEM/XDR platform
- [LMStudio](https://lmstudio.ai/) - Local LLM inference
- [n8n](https://n8n.io/) - Workflow automation
- [pfSense](https://www.pfsense.org/) - Open source firewall
- [AdGuard Home](https://adguard.com/en/adguard-home/overview.html) - DNS server

## 📧 Contact

Created by [@Trac3er00](https://github.com/Trac3er00)
