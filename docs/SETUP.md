# Detailed Setup Guide

This guide walks you through setting up the Wazuh AI-Powered SIEM stack step by step.

## Prerequisites

### Hardware Requirements
- **Wazuh Server**: 6+ cores, 16GB+ RAM, 100GB+ disk
- **LMStudio Server**: GPU recommended (or use Ollama with CPU)

### Software Requirements
- Ubuntu 24.04 LTS
- Wazuh 4.14+ installed and running
- Python 3.10+
- pfSense with SSH access
- AdGuard Home with Wazuh agent
- n8n instance
- Discord server with webhook

## Step 1: Install Wazuh

If you haven't installed Wazuh yet:

```bash
# Download and run Wazuh installer
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh
chmod +x wazuh-install.sh
sudo ./wazuh-install.sh -a

# Note the admin password displayed at the end
```

## Step 2: Configure pfSense Syslog

On your pfSense:

1. Go to **Status > System Logs > Settings**
2. Check **Enable Remote Logging**
3. Set **Remote log servers**: `10.10.0.27:514` (your Wazuh IP)
4. Check all log types you want to forward
5. Save

On Wazuh server, enable syslog receiver:

```bash
# Add to /var/ossec/etc/ossec.conf inside <ossec_config>
sudo nano /var/ossec/etc/ossec.conf
```

Add:
```xml
<remote>
  <connection>syslog</connection>
  <port>514</port>
  <protocol>udp</protocol>
  <allowed-ips>10.10.0.0/23</allowed-ips>
</remote>
```

## Step 3: Install Wazuh Agent on AdGuard

On your AdGuard server:

```bash
# Download agent
curl -so wazuh-agent.deb https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.14.2-1_amd64.deb

# Install with manager IP
sudo WAZUH_MANAGER='10.10.0.27' dpkg -i wazuh-agent.deb

# Start agent
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
```

Configure agent to monitor AdGuard logs:

```bash
# Add to /var/ossec/etc/ossec.conf on AdGuard server
sudo nano /var/ossec/etc/ossec.conf
```

Add inside `<ossec_config>`:
```xml
<localfile>
  <log_format>json</log_format>
  <location>/opt/AdGuardHome/data/querylog.json</location>
</localfile>
```

## Step 4: Set Up LMStudio

1. Download LMStudio from https://lmstudio.ai/
2. Install a model (recommended: `qwen/qwen3-14b` or `llama3-8b`)
3. Start the local server on port 1234
4. Note the server IP (e.g., `10.10.0.136:1234`)

Test connectivity:
```bash
curl http://10.10.0.136:1234/v1/models
```

## Step 5: Create SSH Key for pfSense

```bash
# Generate key
sudo ssh-keygen -t ed25519 -f /etc/ssh/pfsense_automation -N ""

# Copy public key to pfSense
cat /etc/ssh/pfsense_automation.pub
# Add this to pfSense: System > User Manager > admin > Authorized Keys

# Test connection
ssh -i /etc/ssh/pfsense_automation -p 2020 admin@10.10.0.1 "echo success"
```

## Step 6: Set Up Discord Webhook

1. In Discord, go to your server
2. **Server Settings > Integrations > Webhooks**
3. Create new webhook
4. Copy the webhook URL

## Step 7: Set Up n8n

1. Install n8n or use n8n cloud
2. Create SSH credential for Wazuh server:
   - Name: `Wazuh Server`
   - Host: `10.10.0.27`
   - Port: `22`
   - Username: `root`
   - Authentication: SSH Key
   - Private Key: contents of `/etc/ssh/pfsense_automation`

3. Import workflows from `n8n-workflows/` directory
4. Update Discord webhook URL in each workflow
5. Activate all workflows

## Step 8: Run Setup Script

```bash
# Clone repo
git clone https://github.com/Trac3er00/wazuh-ai-siem.git
cd wazuh-ai-siem

# Edit configuration in setup.sh
nano scripts/setup.sh

# Run setup
chmod +x scripts/setup.sh
sudo ./scripts/setup.sh
```

## Step 9: Add Integrations to ossec.conf

```bash
sudo nano /var/ossec/etc/ossec.conf
```

Add inside `<ossec_config>`:

```xml
<!-- DNS AI Integration -->
<integration>
  <name>custom-ai-dns-discord</name>
  <hook_url>placeholder</hook_url>
  <level>3</level>
  <rule_id>111001</rule_id>
  <alert_format>json</alert_format>
</integration>

<!-- pfSense AI Integration -->
<integration>
  <name>custom-pfsense-ai-discord</name>
  <hook_url>placeholder</hook_url>
  <level>8</level>
  <rule_id>112010,112011</rule_id>
  <alert_format>json</alert_format>
</integration>

<!-- SSH Integration -->
<integration>
  <name>custom-ssh-discord</name>
  <hook_url>placeholder</hook_url>
  <level>6</level>
  <group>sshd,authentication_failed</group>
  <alert_format>json</alert_format>
</integration>
```

Restart Wazuh:
```bash
sudo systemctl restart wazuh-manager
```

## Step 10: Create pfSense Firewall Rule

On pfSense:

1. Go to **Firewall > Aliases > Tables**
2. Create table named `quarantine`
3. Go to **Firewall > Rules > WAN** (or LAN)
4. Add rule:
   - Action: Block
   - Source: Table `quarantine`
   - Destination: Any
   - Description: Quarantine blocked devices

## Step 11: Verify Services

```bash
# Check all services
sudo systemctl status wazuh-manager
sudo systemctl status wazuh-threat-hunter
sudo systemctl status wazuh-mcp

# Test Threat Hunter
curl http://localhost:8080/

# Test MCP Server
curl http://localhost:8081/

# Test Chat UI
curl http://localhost:8081/ui
```

## Step 12: Test Integrations

```bash
# Test SSH brute force detection
# From another machine:
ssh fakeuser@wazuh-server
# Enter wrong password 6 times

# Check Discord for alert
```

## Troubleshooting

### No alerts in Discord
```bash
# Check debug logs
cat /tmp/ai-dns-debug.log
cat /tmp/pfsense-ai-debug.log
cat /tmp/ssh-discord-debug.log

# Check Wazuh logs
sudo tail -f /var/ossec/logs/ossec.log
```

### Threat Hunter not starting
```bash
# Check logs
sudo journalctl -u wazuh-threat-hunter -f

# Reinstall dependencies
sudo /opt/threat-hunter-venv/bin/pip install --upgrade langchain langchain-community
```

### pfSense quarantine not working
```bash
# Test SSH connection
ssh -i /etc/ssh/pfsense_automation -p 2020 admin@10.10.0.1

# Test quarantine manually
/usr/local/bin/pfsense-quarantine.sh block 192.168.99.99
/usr/local/bin/pfsense-quarantine.sh list
/usr/local/bin/pfsense-quarantine.sh unblock 192.168.99.99
```
