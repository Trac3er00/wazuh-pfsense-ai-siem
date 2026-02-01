# Troubleshooting Guide

This guide covers common issues and solutions for the Wazuh + pfSense + AI SIEM stack.

## Table of Contents

- [AI/LM Studio Issues](#ailm-studio-issues)
- [Wazuh Agent Issues](#wazuh-agent-issues)
- [Log Forwarding Issues](#log-forwarding-issues)
- [Active Response Issues](#active-response-issues)
- [Grafana Issues](#grafana-issues)
- [Performance Issues](#performance-issues)

---

## AI/LM Studio Issues

### AI Returns "UNREACHABLE"

**Symptoms:**
```
WARNING: AI unavailable (UNREACHABLE) - using fallback rules
```

**Solutions:**

1. **Verify LM Studio is running:**
   ```bash
   # From pfSense
   curl -s http://YOUR_MAC_IP:1234/v1/models
   ```
   Should return a list of models.

2. **Check firewall rules:**
   - Ensure pfSense allows outbound connections to port 1234
   - Check Mac firewall settings

3. **Verify network connectivity:**
   ```bash
   ping YOUR_MAC_IP
   ```

4. **Check LM Studio API server:**
   - Open LM Studio
   - Go to Local Server tab
   - Ensure "Start Server" is enabled
   - Default port should be 1234

### AI Returns "ERROR" (Invalid JSON)

**Symptoms:**
```
AI ERROR: Invalid body: failed to parse JSON value
```

**Solutions:**

1. **Check for special characters in logs:**
   The script sanitizes input, but unusual characters may slip through.
   
2. **Increase timeout:**
   Edit `ai-firewall-block.sh`:
   ```bash
   # Change from 15 to 30 seconds
   RESP=$(curl -s -m 30 -X POST "$AI_URL" ...
   ```

3. **Test with simple payload:**
   ```bash
   curl -s -X POST "http://YOUR_MAC_IP:1234/v1/chat/completions" \
     -H "Content-Type: application/json" \
     -d '{"model":"qwen/qwen3-14b","messages":[{"role":"user","content":"Say hello"}],"max_tokens":50}'
   ```

### AI Makes Wrong Decisions

**Solutions:**

1. **Lower temperature for more consistent output:**
   Edit the script, change `"temperature":0.0` (already set to 0)

2. **Review the prompt:**
   The prompt in `ai-firewall-block.sh` can be adjusted for your needs

3. **Check model performance:**
   Different models have different capabilities. Qwen3-14B works well, but you can try others.

---

## Wazuh Agent Issues

### Agent Not Connecting

**Symptoms:**
```bash
/var/ossec/bin/agent_control -l
# Shows agent as "Disconnected"
```

**Solutions:**

1. **Check agent status:**
   ```bash
   # On pfSense
   /var/ossec/bin/wazuh-control status
   ```

2. **Verify manager address:**
   ```bash
   cat /var/ossec/etc/ossec.conf | grep -A5 "<server>"
   ```

3. **Check network connectivity:**
   ```bash
   # From pfSense
   nc -zv WAZUH_MANAGER_IP 1514
   ```

4. **Review agent logs:**
   ```bash
   tail -50 /var/ossec/logs/ossec.log
   ```

5. **Re-register agent:**
   ```bash
   # On Wazuh Manager
   /var/ossec/bin/manage_agents -l
   /var/ossec/bin/manage_agents -r AGENT_ID
   
   # Re-add agent
   /var/ossec/bin/manage_agents -a
   ```

### Agent Key Mismatch

**Symptoms:**
```
ERROR: Unable to verify server certificate
```

**Solutions:**

1. **Re-extract and import key:**
   ```bash
   # On Manager
   /var/ossec/bin/manage_agents -e AGENT_ID
   
   # On Agent (pfSense)
   /var/ossec/bin/manage_agents -i "KEY_STRING"
   
   # Restart agent
   /var/ossec/bin/wazuh-control restart
   ```

---

## Log Forwarding Issues

### No pfSense Logs in Wazuh

**Solutions:**

1. **Verify syslog is enabled on pfSense:**
   - Status → System Logs → Settings
   - Enable "Send log messages to remote syslog server"
   - Remote log server: `WAZUH_IP:514`

2. **Check Wazuh is listening:**
   ```bash
   # On Wazuh server
   docker exec wazuh.manager ss -ulnp | grep 514
   ```

3. **Test syslog manually:**
   ```bash
   # From any machine
   echo "<14>Test message" | nc -u WAZUH_IP 514
   
   # Check archives
   docker exec wazuh.manager tail /var/ossec/logs/archives/archives.log
   ```

4. **Check firewall rules:**
   Ensure UDP 514 is allowed to Wazuh VM

### Logs Arriving But Not Decoded

**Symptoms:**
- Logs appear in archives but not as alerts
- No `srcip` or `dstip` fields extracted

**Solutions:**

1. **Test decoder:**
   ```bash
   docker exec wazuh.manager /var/ossec/bin/wazuh-logtest
   # Paste a sample pfSense log line
   ```

2. **Check decoder is loaded:**
   ```bash
   docker exec wazuh.manager ls /var/ossec/etc/decoders/
   # Should see pfsense-decoder.xml
   ```

3. **Restart manager after adding decoders:**
   ```bash
   docker restart wazuh.manager
   ```

---

## Active Response Issues

### Active Response Not Triggering

**Solutions:**

1. **Verify configuration:**
   ```bash
   docker exec wazuh.manager cat /var/ossec/etc/ossec.conf | grep -A20 "active-response"
   ```

2. **Check agent ID is correct:**
   ```bash
   docker exec wazuh.manager /var/ossec/bin/agent_control -l
   # Note your pfSense agent ID
   ```

3. **Verify script exists on agent:**
   ```bash
   # On pfSense
   ls -la /var/ossec/active-response/bin/ai-firewall-block.sh
   ```

4. **Check script permissions:**
   ```bash
   chmod 750 /var/ossec/active-response/bin/ai-firewall-block.sh
   chown root:wheel /var/ossec/active-response/bin/ai-firewall-block.sh
   ```

5. **Test script manually:**
   ```bash
   echo '{"parameters":{"alert":{"data":{"srcip":"1.2.3.4","dstport":"22"},"rule":{"id":"110002","level":"10","description":"Test"}}}}' | /var/ossec/active-response/bin/ai-firewall-block.sh
   ```

### IPs Not Being Blocked

**Solutions:**

1. **Check pfctl table:**
   ```bash
   pfctl -t snort2c -T show
   ```

2. **Manually test blocking:**
   ```bash
   pfctl -t snort2c -T add 1.2.3.4
   pfctl -t snort2c -T show
   pfctl -t snort2c -T delete 1.2.3.4
   ```

3. **Verify jq is installed:**
   ```bash
   which jq
   # Should show /usr/local/bin/jq
   
   # If not:
   pkg install -y jq
   ```

4. **Check logs:**
   ```bash
   tail -20 /var/ossec/logs/active-responses.log
   tail -20 /var/ossec/logs/ai-decisions.log
   ```

---

## Grafana Issues

### Cannot Connect to OpenSearch

**Symptoms:**
- Data source test fails
- "Bad Gateway" or "Connection refused"

**Solutions:**

1. **Verify Wazuh Indexer is running:**
   ```bash
   docker ps | grep indexer
   curl -k -u admin:PASSWORD https://localhost:9200
   ```

2. **Check Grafana network:**
   ```bash
   # Grafana must be on same Docker network
   docker network inspect wazuh-network
   ```

3. **Use correct URL:**
   - From Grafana container: `https://wazuh.indexer:9200`
   - With SSL verification disabled

4. **Check credentials:**
   - Username: `admin`
   - Password: Your INDEXER_PASSWORD

### No Data in Dashboards

**Solutions:**

1. **Check time range:**
   - Default is "Last 24 hours"
   - Adjust if needed

2. **Verify index pattern:**
   - Should be `wazuh-alerts-*`

3. **Check indices exist:**
   ```bash
   curl -k -u admin:PASSWORD https://localhost:9200/_cat/indices | grep wazuh
   ```

4. **Generate test data:**
   Trigger a rule manually to create alerts

---

## Performance Issues

### High CPU on Wazuh Manager

**Solutions:**

1. **Increase resources:**
   Edit docker-compose.yml:
   ```yaml
   wazuh.manager:
     deploy:
       resources:
         limits:
           cpus: '2'
           memory: 4G
   ```

2. **Reduce log volume:**
   - Filter logs at pfSense level
   - Increase frequency thresholds in rules

### High Memory on Wazuh Indexer

**Solutions:**

1. **Adjust Java heap:**
   ```yaml
   environment:
     - "OPENSEARCH_JAVA_OPTS=-Xms2g -Xmx2g"
   ```

2. **Configure index retention:**
   Delete old indices:
   ```bash
   curl -k -u admin:PASSWORD -X DELETE "https://localhost:9200/wazuh-alerts-4.x-2024.01.*"
   ```

### Slow AI Responses

**Solutions:**

1. **Use faster model:**
   - Qwen3-8B instead of 14B
   - Or any smaller model

2. **Increase timeout:**
   Edit script: `-m 30` instead of `-m 15`

3. **Reduce max_tokens:**
   Edit script: `"max_tokens":80` instead of 120

---

## Getting Help

If you're still stuck:

1. **Check Wazuh documentation:** https://documentation.wazuh.com
2. **Wazuh GitHub issues:** https://github.com/wazuh/wazuh/issues
3. **Wazuh Slack community:** https://wazuh.com/community/

When reporting issues, include:
- Wazuh version (`docker exec wazuh.manager cat /var/ossec/etc/ossec-init.conf`)
- Relevant log excerpts
- Steps to reproduce
