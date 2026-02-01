# Troubleshooting Guide

Common issues and solutions for the Wazuh AI SIEM stack.

## Table of Contents
- [No Alerts in Discord](#no-alerts-in-discord)
- [AI Analysis Not Working](#ai-analysis-not-working)
- [Threat Hunter Issues](#threat-hunter-issues)
- [MCP Server Issues](#mcp-server-issues)
- [pfSense Quarantine Not Working](#pfsense-quarantine-not-working)
- [n8n Webhook Issues](#n8n-webhook-issues)
- [High CPU/Memory Usage](#high-cpumemory-usage)

---

## No Alerts in Discord

### Check integration scripts are properly installed

```bash
# Verify scripts exist and have correct permissions
ls -la /var/ossec/integrations/custom-*

# Expected output:
# -rwxr-x--- root wazuh custom-ai-dns-discord
# -rwxr-x--- root wazuh custom-ai-dns-discord.py
# -rwxr-x--- root wazuh custom-pfsense-ai-discord
# -rwxr-x--- root wazuh custom-pfsense-ai-discord.py
# -rwxr-x--- root wazuh custom-ssh-discord
# -rwxr-x--- root wazuh custom-ssh-discord.py
```

### Check debug logs

```bash
# DNS integration
cat /tmp/ai-dns-debug.log | tail -50

# pfSense integration  
cat /tmp/pfsense-ai-debug.log | tail -50

# SSH integration
cat /tmp/ssh-discord-debug.log | tail -50
```

### Test Discord webhook manually

```bash
curl -X POST "YOUR_DISCORD_WEBHOOK_URL" \
  -H "Content-Type: application/json" \
  -d '{"content": "Test message from Wazuh"}'
```

### Verify integration is configured in ossec.conf

```bash
sudo grep -A5 "custom-ai-dns-discord\|custom-pfsense-ai-discord\|custom-ssh-discord" /var/ossec/etc/ossec.conf
```

### Check Wazuh integration logs

```bash
sudo tail -f /var/ossec/logs/integrations.log
```

---

## AI Analysis Not Working

### Check LMStudio/Ollama is running

```bash
curl http://10.10.0.136:1234/v1/models
# Should return list of models
```

### Check network connectivity from Wazuh to AI server

```bash
curl -X POST http://10.10.0.136:1234/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"qwen/qwen3-14b","messages":[{"role":"user","content":"hello"}],"max_tokens":10}'
```

### Check firewall rules

Make sure port 1234 is open between Wazuh and LMStudio servers.

### Test AI from integration script

```bash
# Create test alert
cat > /tmp/test.alert << 'EOF'
{
  "timestamp": "2026-02-01T12:00:00.000+0000",
  "rule": {"level": 5, "id": "111001"},
  "data": {"QH": "test-domain.xyz", "IP": "10.10.0.100", "IsFiltered": "false"}
}
EOF

# Run DNS integration manually
sudo python3 /var/ossec/integrations/custom-ai-dns-discord.py /tmp/test.alert

# Check result
cat /tmp/ai-dns-debug.log | tail -20
```

---

## Threat Hunter Issues

### Service not starting

```bash
# Check service status
sudo systemctl status wazuh-threat-hunter

# Check logs
sudo journalctl -u wazuh-threat-hunter -f

# Common issue: missing dependencies
sudo /opt/threat-hunter-venv/bin/pip install --upgrade \
  langchain langchain-community langchain-huggingface \
  faiss-cpu sentence-transformers
```

### Vector store not loading

```bash
# Check if archives exist
ls -la /var/ossec/logs/archives/

# Check archive content
head -5 /var/ossec/logs/archives/archives.json

# If empty, enable archive logging:
sudo sed -i 's/<logall>no/<logall>yes/g' /var/ossec/etc/ossec.conf
sudo sed -i 's/<logall_json>no/<logall_json>yes/g' /var/ossec/etc/ossec.conf
sudo systemctl restart wazuh-manager
```

### Slow query responses

The initial vector store build takes 3-5 minutes for ~3000 documents. This is normal. Subsequent queries should be faster.

```bash
# Check stats
curl http://localhost:8080/stats
```

---

## MCP Server Issues

### Authentication failing

```bash
# Find correct Wazuh API password
sudo grep "password" /usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml

# Update MCP server with correct password
sudo nano /opt/wazuh-mcp/server.py
# Change WAZUH_PASS value

# Restart
sudo systemctl restart wazuh-mcp
```

### Test MCP endpoints

```bash
# Status
curl http://localhost:8081/

# Agents
curl http://localhost:8081/agents

# Alerts summary  
curl http://localhost:8081/alerts/summary
```

### Web UI not loading

```bash
# Check if server is running
sudo systemctl status wazuh-mcp

# Test UI endpoint
curl http://localhost:8081/ui | head -20
```

---

## pfSense Quarantine Not Working

### Test SSH connection

```bash
# Test SSH key auth
ssh -i /etc/ssh/pfsense_automation -p 2020 admin@10.10.0.1 "echo success"

# If fails, regenerate key:
sudo ssh-keygen -t ed25519 -f /etc/ssh/pfsense_automation -N ""
cat /etc/ssh/pfsense_automation.pub
# Add to pfSense: System > User Manager > admin > Authorized Keys
```

### Test quarantine script manually

```bash
# Test block (use a test IP)
sudo /usr/local/bin/pfsense-quarantine.sh block 192.168.99.99 "test"

# List quarantined IPs
sudo /usr/local/bin/pfsense-quarantine.sh list

# Unblock
sudo /usr/local/bin/pfsense-quarantine.sh unblock 192.168.99.99
```

### Check protected IPs

```bash
# Make sure you're not trying to quarantine a protected IP
grep "PROTECTED_IPS" /usr/local/bin/pfsense-quarantine.sh
```

### Verify pfSense quarantine table exists

On pfSense:
1. Go to Firewall > Aliases > Tables
2. Ensure "quarantine" table exists
3. Check Firewall > Rules has block rule using this table

---

## n8n Webhook Issues

### Webhook not responding

```bash
# Test webhook directly
curl -X GET "https://n8n.yourserver.com/webhook/wazuh-quarantine?ip=test"
```

### SSH credential issues in n8n

1. Go to n8n > Credentials
2. Edit Wazuh Server credential
3. Verify:
   - Host: 10.10.0.27
   - Port: 22
   - Username: root (or wazuh-user)
   - Authentication: SSH Key
   - Private Key: contents of /etc/ssh/pfsense_automation

### Workflow not triggering

1. Check workflow is activated (green toggle)
2. Check webhook URL matches what's in Discord alert
3. Check n8n execution logs

---

## High CPU/Memory Usage

### Wazuh Manager

```bash
# Check log volume
sudo wc -l /var/ossec/logs/alerts/alerts.json

# If too many alerts, tune rules:
# - Increase threshold levels
# - Add more suppression rules
```

### Threat Hunter

```bash
# Reduce vector store size by limiting hours
# Edit /var/ossec/integrations/threat_hunter.py
# Change default hours from 24 to 12 or 6

# Restart
sudo systemctl restart wazuh-threat-hunter
```

### LMStudio

- Reduce context window size
- Use a smaller model (e.g., 7B instead of 14B)
- Enable GPU offloading if available

---

## Quick Diagnostic Commands

```bash
# All services status
echo "=== Wazuh Manager ===" && sudo systemctl is-active wazuh-manager
echo "=== Threat Hunter ===" && sudo systemctl is-active wazuh-threat-hunter  
echo "=== MCP Server ===" && sudo systemctl is-active wazuh-mcp

# Check open ports
sudo ss -tlnp | grep -E "8080|8081|55000|1514|514"

# Recent Wazuh alerts
sudo tail -20 /var/ossec/logs/alerts/alerts.log

# Integration errors
sudo grep -i error /var/ossec/logs/integrations.log | tail -20
```

---

## Getting Help

1. Check the [docs/SETUP.md](SETUP.md) for installation issues
2. Review debug logs in `/tmp/*.log`
3. Open an issue on GitHub with:
   - Error messages
   - Debug log output
   - Steps to reproduce
