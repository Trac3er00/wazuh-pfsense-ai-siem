# 🛡️ Wazuh + pfSense + AI-Powered SIEM

A complete home lab security monitoring stack with AI-enhanced threat detection and automated incident response.

## 🎯 Overview

This project implements a comprehensive security monitoring solution that combines:

- **Wazuh SIEM** - Security Information and Event Management
- **pfSense Firewall** - Network perimeter security with log forwarding
- **Local AI (LM Studio)** - Intelligent threat analysis using Qwen3-14B
- **Grafana** - Real-time security dashboards
- **Automated Active Response** - AI-powered IP blocking with failsafe

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              NETWORK                                         │
│  ┌──────────────┐      ┌──────────────┐      ┌──────────────┐              │
│  │   Internet   │──────│   pfSense    │──────│   LAN/DMZ    │              │
│  │              │      │  (Firewall)  │      │   Devices    │              │
│  └──────────────┘      └──────┬───────┘      └──────────────┘              │
│                               │                                             │
│                               │ Syslog (UDP 514)                           │
│                               │ Wazuh Agent                                │
│                               ▼                                             │
│  ┌──────────────────────────────────────────────────────────────┐          │
│  │                    WAZUH VM (Proxmox)                        │          │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          │          │
│  │  │   Wazuh     │  │   Wazuh     │  │   Wazuh     │          │          │
│  │  │   Manager   │  │  Indexer    │  │  Dashboard  │          │          │
│  │  │   :1514     │  │   :9200     │  │   :443      │          │          │
│  │  └─────────────┘  └──────┬──────┘  └─────────────┘          │          │
│  │                          │                                   │          │
│  │                   ┌──────▼──────┐                           │          │
│  │                   │   Grafana   │                           │          │
│  │                   │    :3000    │                           │          │
│  │                   └─────────────┘                           │          │
│  └──────────────────────────────────────────────────────────────┘          │
│                               │                                             │
│                               │ API Call                                   │
│                               ▼                                             │
│  ┌──────────────────────────────────────────────────────────────┐          │
│  │                    MAC (LM Studio)                           │          │
│  │                   Qwen3-14B Model                            │          │
│  │                      :1234                                   │          │
│  └──────────────────────────────────────────────────────────────┘          │
└─────────────────────────────────────────────────────────────────────────────┘
```

## ✨ Features

### 🔍 Log Collection & Analysis
- Real-time pfSense firewall log ingestion via syslog
- Custom decoders for pfSense filterlog format
- Field extraction: source/dest IP, ports, protocol, interface, action

### 🤖 AI-Powered Threat Detection
- Local LLM integration (Qwen3-14B via LM Studio)
- Intelligent blocking decisions based on threat severity
- Automatic failsafe when AI is unreachable
- No cloud dependencies - 100% local processing

### ⚡ Automated Active Response
- Dynamic IP blocking with configurable durations:
  - **Level 0-6 (Low)**: No block
  - **Level 7-9 (Medium)**: 5 minute block
  - **Level 10-11 (High)**: 15 minute block  
  - **Level 12-15 (Critical)**: 1 hour block
- Sensitive port detection (SSH, RDP, databases)
- Automatic unblock after timeout

### 📊 Real-Time Dashboards
- Grafana dashboards with OpenSearch data source
- Visualizations: alerts over time, top attackers, targeted ports
- Auto-refresh every 30 seconds

## 📋 Prerequisites

- **Proxmox VE** (or any hypervisor)
- **pfSense** firewall (2.7.x recommended)
- **Docker & Docker Compose**
- **LM Studio** (for local AI) - [Download](https://lmstudio.ai/)
- Minimum 8GB RAM for Wazuh VM
- Minimum 16GB RAM for AI workstation

## 🚀 Quick Start

### Phase 1: Deploy Wazuh

```bash
# Clone Wazuh Docker repository
git clone https://github.com/wazuh/wazuh-docker.git
cd wazuh-docker/single-node

# Generate certificates
docker compose -f generate-indexer-certs.yml run --rm generator

# Start the stack
docker compose up -d
```

Access Wazuh Dashboard: `https://YOUR_IP:443`
- Username: `admin`
- Password: `SecretPassword` (change this!)

### Phase 2: Configure pfSense Log Forwarding

1. **Enable Remote Syslog** in pfSense:
   - Status → System Logs → Settings
   - Enable "Send log messages to remote syslog server"
   - Remote log server: `YOUR_WAZUH_IP:514`
   - Check: Firewall Events

2. **Install Wazuh Agent** on pfSense:
   ```bash
   # SSH to pfSense
   pkg install -y wazuh-agent
   
   # Configure agent
   cat > /var/ossec/etc/ossec.conf << 'EOF'
   <ossec_config>
     <client>
       <server>
         <address>YOUR_WAZUH_MANAGER_IP</address>
         <port>1514</port>
         <protocol>tcp</protocol>
       </server>
     </client>
   </ossec_config>
   EOF
   
   # Start agent
   /var/ossec/bin/wazuh-control start
   ```

### Phase 3: Deploy AI-Enhanced Active Response

1. **Copy the script to pfSense**:
   ```bash
   scp -P 22 scripts/ai-firewall-block.sh admin@PFSENSE_IP:/var/ossec/active-response/bin/
   ```

2. **Set permissions**:
   ```bash
   chmod 750 /var/ossec/active-response/bin/ai-firewall-block.sh
   chown root:wheel /var/ossec/active-response/bin/ai-firewall-block.sh
   ```

3. **Install jq** (required for JSON parsing):
   ```bash
   pkg install -y jq
   ```

4. **Configure Wazuh Manager**:
   ```bash
   # Add to ossec.conf before </ossec_config>
   docker exec -i wazuh.manager bash -c 'cat >> /var/ossec/etc/ossec.conf << "EOF"
   
     <!-- AI-Enhanced Active Response -->
     <command>
       <name>ai-firewall-block</name>
       <executable>ai-firewall-block.sh</executable>
       <timeout_allowed>yes</timeout_allowed>
     </command>
   
     <active-response>
       <command>ai-firewall-block</command>
       <location>defined-agent</location>
       <agent_id>002</agent_id>
       <rules_id>110002</rules_id>
     </active-response>
   EOF'
   
   # Restart manager
   docker restart wazuh.manager
   ```

### Phase 4: Setup Grafana

1. **Add Grafana to docker-compose.yml**:
   ```yaml
   grafana:
     image: grafana/grafana:11.5.1
     container_name: grafana
     ports:
       - "3000:3000"
     environment:
       - GF_SECURITY_ADMIN_PASSWORD=YourSecurePassword
     volumes:
       - grafana-data:/var/lib/grafana
     networks:
       - wazuh-network
   ```

2. **Start Grafana**:
   ```bash
   docker compose up -d grafana
   ```

3. **Configure OpenSearch Data Source**:
   - URL: `https://wazuh.indexer:9200`
   - Basic Auth: `admin` / `YOUR_INDEXER_PASSWORD`
   - Skip TLS Verify: enabled

## 📁 Project Structure

```
wazuh-pfsense-ai-siem/
├── README.md
├── LICENSE
├── docker-compose.yml
├── scripts/
│   └── ai-firewall-block.sh      # AI-enhanced active response
├── wazuh-config/
│   ├── decoders/
│   │   └── pfsense-decoder.xml   # Custom pfSense log decoder
│   ├── rules/
│   │   └── pfsense-rules.xml     # Custom detection rules
│   └── ossec.conf.example        # Manager configuration
├── grafana/
│   └── dashboards/
│       └── pfsense-security.json # Pre-built dashboard
└── docs/
    ├── images/
    └── troubleshooting.md
```

## 🔧 Configuration

### AI Configuration (ai-firewall-block.sh)

```bash
# LM Studio endpoint
AI_URL="http://YOUR_MAC_IP:1234/v1/chat/completions"
AI_MODEL="qwen/qwen3-14b"

# Block durations (seconds)
SHORT=300    # 5 minutes
MEDIUM=900   # 15 minutes
LONG=3600    # 1 hour
```

### Custom Detection Rules

```xml
<!-- Port Scan Detection -->
<rule id="110002" level="10" frequency="5" timeframe="60">
  <if_matched_sid>110001</if_matched_sid>
  <same_source_ip />
  <description>pfSense: Possible port scan detected from $(srcip)</description>
  <group>pfsense,attack,scan</group>
</rule>
```

## 📊 Dashboard Panels

| Panel | Description |
|-------|-------------|
| Total Alerts (24h) | Count of all security events |
| Blocked Connections | Firewall block actions |
| Unique Source IPs | Distinct attackers |
| High Severity Alerts | Level 10+ events |
| Active Agents | Connected Wazuh agents |
| Firewall Events Over Time | Time series graph |
| Top 10 Source IPs | Most active attackers |
| Top 10 Destination Ports | Most targeted services |
| Alerts by Severity | Distribution by level |
| Recent High Severity | Alert details table |

## 🧪 Testing

### Test AI Decision Making

```bash
# Test Level 10 alert (should block 15min)
echo '{"parameters":{"alert":{"data":{"srcip":"198.51.100.1","dstport":"22"},"rule":{"id":"110002","level":"10","description":"SSH scan"}}}}' | /var/ossec/active-response/bin/ai-firewall-block.sh

# Check AI decision log
tail -10 /var/ossec/logs/ai-decisions.log

# Verify block
pfctl -t snort2c -T show
```

### Test Fallback Mode

```bash
# Stop LM Studio, then run test
# Should show "AI down, using fallback"
tail -5 /var/ossec/logs/ai-decisions.log
```

## 🔒 Security Hardening

**Important**: Change all default passwords!

```bash
# Grafana
docker exec -it grafana grafana-cli admin reset-admin-password 'NewSecurePassword!'

# Wazuh Indexer - update in docker-compose.yml
INDEXER_PASSWORD=NewSecurePassword

# Generate secure passwords
openssl rand -base64 24
```

## 🐛 Troubleshooting

### AI Returns "UNREACHABLE"
- Verify LM Studio is running with API server enabled
- Check network connectivity: `curl -s http://MAC_IP:1234/v1/models`
- Verify firewall allows traffic on port 1234

### No Logs in Grafana
- Check Wazuh Indexer: `curl -k -u admin:password https://localhost:9200/_cat/indices`
- Verify time range in Grafana (default: Last 24 hours)
- Check index pattern matches `wazuh-alerts-*`

### Active Response Not Triggering
- Verify agent is connected: `/var/ossec/bin/agent_control -l`
- Check ossec.conf has correct agent_id
- Review manager logs: `docker logs wazuh.manager`

## 📝 License

MIT License - See [LICENSE](LICENSE) for details.

## 🙏 Acknowledgments

- [Wazuh](https://wazuh.com/) - Open source security platform
- [pfSense](https://www.pfsense.org/) - Open source firewall
- [LM Studio](https://lmstudio.ai/) - Local LLM runner
- [Grafana](https://grafana.com/) - Observability platform

## 📧 Contact

Created by [@cminseo](https://github.com/cminseo) - Feel free to reach out!

---

⭐ **Star this repo if you found it helpful!**
