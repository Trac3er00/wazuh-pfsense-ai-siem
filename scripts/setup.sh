#!/bin/bash
#
# Wazuh AI SIEM Setup Script
# Installs and configures all components
#
# Author: @Trac3er00
#

set -e

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║           Wazuh AI-Powered SIEM Setup Script                 ║"
echo "╚══════════════════════════════════════════════════════════════╝"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 
   exit 1
fi

# =============================================================================
# CONFIGURATION - Edit these before running!
# =============================================================================

echo ""
echo "Please edit the configuration variables at the top of this script"
echo "before running the setup."
echo ""
echo "Required configuration:"
echo "  - DISCORD_WEBHOOK: Your Discord webhook URL"
echo "  - N8N_BASE_URL: Your n8n webhook base URL"
echo "  - LMSTUDIO_URL: Your LMStudio/Ollama server URL"
echo "  - PFSENSE_HOST: Your pfSense IP address"
echo "  - WAZUH_API_PASS: Your Wazuh API password"
echo ""

# Default values - EDIT THESE
DISCORD_WEBHOOK="YOUR_DISCORD_WEBHOOK_HERE"
N8N_BASE_URL="https://n8n.yourserver.com/webhook"
LMSTUDIO_URL="http://10.10.0.136:1234/v1/chat/completions"
LMSTUDIO_MODEL="qwen/qwen3-14b"
PFSENSE_HOST="10.10.0.1"
PFSENSE_SSH_PORT="2020"
WAZUH_API_PASS="YOUR_WAZUH_API_PASSWORD"

# =============================================================================
# STEP 1: Install Dependencies
# =============================================================================

echo "[1/8] Installing system dependencies..."
apt update
apt install -y python3.12-venv python3-pip

# =============================================================================
# STEP 2: Copy Integration Scripts
# =============================================================================

echo "[2/8] Installing integration scripts..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Copy integrations
cp "$SCRIPT_DIR/integrations/custom-ai-dns-discord.py" /var/ossec/integrations/
cp "$SCRIPT_DIR/integrations/custom-pfsense-ai-discord.py" /var/ossec/integrations/
cp "$SCRIPT_DIR/integrations/custom-ssh-discord.py" /var/ossec/integrations/

# Update configuration in scripts
sed -i "s|YOUR_DISCORD_WEBHOOK_HERE|$DISCORD_WEBHOOK|g" /var/ossec/integrations/custom-*.py
sed -i "s|https://n8n.yourserver.com/webhook|$N8N_BASE_URL|g" /var/ossec/integrations/custom-*.py
sed -i "s|http://10.10.0.136:1234/v1/chat/completions|$LMSTUDIO_URL|g" /var/ossec/integrations/custom-*.py

# Create shell wrappers
for script in custom-ai-dns-discord custom-pfsense-ai-discord custom-ssh-discord; do
    cat > /var/ossec/integrations/$script << EOF
#!/bin/sh
/var/ossec/integrations/${script}.py "\$@"
EOF
done

# Set permissions
chmod 750 /var/ossec/integrations/custom-*
chown root:wazuh /var/ossec/integrations/custom-*

# =============================================================================
# STEP 3: Copy Rules and Decoders
# =============================================================================

echo "[3/8] Installing rules and decoders..."
cp "$SCRIPT_DIR/rules/local_rules.xml" /var/ossec/etc/rules/
cp "$SCRIPT_DIR/rules/pfsense_custom_rules.xml" /var/ossec/etc/rules/
cp "$SCRIPT_DIR/rules/local_adguard_rules.xml" /var/ossec/etc/rules/
cp "$SCRIPT_DIR/decoders/adguard_decoder.xml" /var/ossec/etc/decoders/

chown wazuh:wazuh /var/ossec/etc/rules/*.xml
chown wazuh:wazuh /var/ossec/etc/decoders/*.xml

# =============================================================================
# STEP 4: Create ignored domains file
# =============================================================================

echo "[4/8] Creating ignored domains file..."
touch /var/ossec/etc/lists/ignored-domains.txt
chown wazuh:wazuh /var/ossec/etc/lists/ignored-domains.txt

# =============================================================================
# STEP 5: Install Threat Hunter
# =============================================================================

echo "[5/8] Setting up AI Threat Hunter..."
python3 -m venv /opt/threat-hunter-venv
/opt/threat-hunter-venv/bin/pip install \
    langchain langchain-community langchain-text-splitters langchain-huggingface \
    langchain-core faiss-cpu sentence-transformers fastapi uvicorn 'uvicorn[standard]' \
    requests python-dateutil httpx

cp "$SCRIPT_DIR/services/threat_hunter.py" /var/ossec/integrations/
sed -i "s|http://10.10.0.136:1234/v1/chat/completions|$LMSTUDIO_URL|g" /var/ossec/integrations/threat_hunter.py

cp "$SCRIPT_DIR/services/wazuh-threat-hunter.service" /etc/systemd/system/

# =============================================================================
# STEP 6: Install MCP Server
# =============================================================================

echo "[6/8] Setting up MCP Server..."
mkdir -p /opt/wazuh-mcp
python3 -m venv /opt/wazuh-mcp/venv
/opt/wazuh-mcp/venv/bin/pip install fastapi uvicorn 'uvicorn[standard]' requests httpx

cp "$SCRIPT_DIR/services/mcp_server.py" /opt/wazuh-mcp/server.py
sed -i "s|YOUR_WAZUH_API_PASSWORD|$WAZUH_API_PASS|g" /opt/wazuh-mcp/server.py

cp "$SCRIPT_DIR/services/wazuh-mcp.service" /etc/systemd/system/

# =============================================================================
# STEP 7: Install pfSense Quarantine Script
# =============================================================================

echo "[7/8] Setting up pfSense quarantine script..."
cp "$SCRIPT_DIR/scripts/pfsense-quarantine.sh" /usr/local/bin/
chmod 755 /usr/local/bin/pfsense-quarantine.sh
sed -i "s|PFSENSE_HOST=\"10.10.0.1\"|PFSENSE_HOST=\"$PFSENSE_HOST\"|g" /usr/local/bin/pfsense-quarantine.sh
sed -i "s|PFSENSE_SSH_PORT=\"2020\"|PFSENSE_SSH_PORT=\"$PFSENSE_SSH_PORT\"|g" /usr/local/bin/pfsense-quarantine.sh

# =============================================================================
# STEP 8: Enable Archives and Start Services
# =============================================================================

echo "[8/8] Enabling archives and starting services..."

# Enable JSON archives
sed -i 's/<logall>no<\/logall>/<logall>yes<\/logall>/g' /var/ossec/etc/ossec.conf
sed -i 's/<logall_json>no<\/logall_json>/<logall_json>yes<\/logall_json>/g' /var/ossec/etc/ossec.conf

# Create debug log files
touch /tmp/ai-dns-debug.log /tmp/pfsense-ai-debug.log /tmp/ssh-discord-debug.log
chmod 666 /tmp/ai-dns-debug.log /tmp/pfsense-ai-debug.log /tmp/ssh-discord-debug.log

# Reload and start services
systemctl daemon-reload
systemctl restart wazuh-manager
systemctl enable wazuh-threat-hunter
systemctl start wazuh-threat-hunter
systemctl enable wazuh-mcp
systemctl start wazuh-mcp

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                    Setup Complete!                           ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "Services:"
echo "  - Wazuh Manager: $(systemctl is-active wazuh-manager)"
echo "  - Threat Hunter: $(systemctl is-active wazuh-threat-hunter)"
echo "  - MCP Server:    $(systemctl is-active wazuh-mcp)"
echo ""
echo "Endpoints:"
echo "  - Wazuh Dashboard: https://localhost"
echo "  - Threat Hunter:   http://localhost:8080"
echo "  - MCP Server:      http://localhost:8081"
echo "  - Chat UI:         http://localhost:8081/ui"
echo ""
echo "Next steps:"
echo "  1. Configure pfSense to send syslog to this server on UDP 514"
echo "  2. Install Wazuh agent on AdGuard server"
echo "  3. Import n8n workflows from n8n-workflows/ directory"
echo "  4. Test integrations with: ./scripts/test-integrations.sh"
echo ""
