#!/bin/bash
#
# Wazuh AI SIEM Integration Test Script
# Tests all components to verify setup is working
#
# Author: @Trac3er00
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║           Wazuh AI SIEM Integration Tests                    ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

PASS=0
FAIL=0

test_result() {
    if [ $1 -eq 0 ]; then
        echo -e "  ${GREEN}✓ PASS${NC}: $2"
        ((PASS++))
    else
        echo -e "  ${RED}✗ FAIL${NC}: $2"
        ((FAIL++))
    fi
}

# =============================================================================
# SERVICE TESTS
# =============================================================================
echo ""
echo "=== Service Status ==="

systemctl is-active --quiet wazuh-manager
test_result $? "Wazuh Manager is running"

systemctl is-active --quiet wazuh-threat-hunter 2>/dev/null
test_result $? "Threat Hunter is running"

systemctl is-active --quiet wazuh-mcp 2>/dev/null
test_result $? "MCP Server is running"

# =============================================================================
# API TESTS
# =============================================================================
echo ""
echo "=== API Connectivity ==="

curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/ | grep -q "200"
test_result $? "Threat Hunter API (port 8080) responds"

curl -s -o /dev/null -w "%{http_code}" http://localhost:8081/ | grep -q "200"
test_result $? "MCP Server API (port 8081) responds"

curl -s http://localhost:8081/agents | grep -q "agents"
test_result $? "MCP Server returns agents list"

# =============================================================================
# LM STUDIO TEST
# =============================================================================
echo ""
echo "=== LMStudio Connectivity ==="

LMSTUDIO_URL="http://10.10.0.136:1234"
curl -s -o /dev/null --connect-timeout 5 "$LMSTUDIO_URL/v1/models" 2>/dev/null
if [ $? -eq 0 ]; then
    test_result 0 "LMStudio API is reachable"
else
    echo -e "  ${YELLOW}⚠ WARN${NC}: LMStudio not reachable at $LMSTUDIO_URL"
    echo -e "         This is OK if you're using a different AI server"
fi

# =============================================================================
# FILE TESTS
# =============================================================================
echo ""
echo "=== Integration Scripts ==="

[ -f /var/ossec/integrations/custom-ai-dns-discord.py ]
test_result $? "DNS integration script exists"

[ -f /var/ossec/integrations/custom-pfsense-ai-discord.py ]
test_result $? "pfSense integration script exists"

[ -f /var/ossec/integrations/custom-ssh-discord.py ]
test_result $? "SSH integration script exists"

[ -x /var/ossec/integrations/custom-ai-dns-discord ]
test_result $? "DNS integration wrapper is executable"

# =============================================================================
# RULES AND DECODERS
# =============================================================================
echo ""
echo "=== Rules and Decoders ==="

[ -f /var/ossec/etc/rules/local_rules.xml ]
test_result $? "Local rules file exists"

[ -f /var/ossec/etc/rules/pfsense_custom_rules.xml ]
test_result $? "pfSense rules file exists"

[ -f /var/ossec/etc/rules/local_adguard_rules.xml ]
test_result $? "AdGuard rules file exists"

[ -f /var/ossec/etc/decoders/adguard_decoder.xml ]
test_result $? "AdGuard decoder exists"

# =============================================================================
# ARCHIVE LOGGING
# =============================================================================
echo ""
echo "=== Archive Logging ==="

grep -q "<logall>yes</logall>" /var/ossec/etc/ossec.conf
test_result $? "Archive logging enabled"

grep -q "<logall_json>yes</logall_json>" /var/ossec/etc/ossec.conf
test_result $? "JSON archive logging enabled"

if [ -f /var/ossec/logs/archives/archives.json ]; then
    LINES=$(wc -l < /var/ossec/logs/archives/archives.json)
    if [ "$LINES" -gt 0 ]; then
        test_result 0 "Archives contain data ($LINES entries)"
    else
        test_result 1 "Archives file is empty"
    fi
else
    test_result 1 "Archives file not found"
fi

# =============================================================================
# PFSENSE QUARANTINE
# =============================================================================
echo ""
echo "=== pfSense Quarantine ==="

[ -f /usr/local/bin/pfsense-quarantine.sh ]
test_result $? "Quarantine script exists"

[ -x /usr/local/bin/pfsense-quarantine.sh ]
test_result $? "Quarantine script is executable"

[ -f /etc/ssh/pfsense_automation ]
test_result $? "pfSense SSH key exists"

# =============================================================================
# THREAT HUNTER TEST
# =============================================================================
echo ""
echo "=== Threat Hunter Query Test ==="

RESPONSE=$(curl -s -X POST http://localhost:8080/query \
  -H "Content-Type: application/json" \
  -d '{"question": "test", "hours": 1, "max_results": 1}' 2>/dev/null)

echo "$RESPONSE" | grep -q "answer"
test_result $? "Threat Hunter returns valid response"

# =============================================================================
# SUMMARY
# =============================================================================
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                       TEST SUMMARY                           ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo -e "  ${GREEN}Passed${NC}: $PASS"
echo -e "  ${RED}Failed${NC}: $FAIL"
echo ""

if [ $FAIL -eq 0 ]; then
    echo -e "${GREEN}All tests passed! Your Wazuh AI SIEM is ready.${NC}"
    exit 0
else
    echo -e "${YELLOW}Some tests failed. Check the issues above.${NC}"
    echo "See docs/TROUBLESHOOTING.md for help."
    exit 1
fi
