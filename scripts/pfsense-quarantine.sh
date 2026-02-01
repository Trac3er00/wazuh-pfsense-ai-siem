#!/bin/bash
#
# pfSense Quarantine Script
# Blocks/unblocks IPs on pfSense firewall via SSH
#
# Location: /usr/local/bin/pfsense-quarantine.sh
# Usage: ./pfsense-quarantine.sh block|unblock|list [ip] [reason]
#
# Author: @Trac3er00
#

# =============================================================================
# CONFIGURATION - Edit these values for your environment
# =============================================================================

PFSENSE_HOST="10.10.0.1"
PFSENSE_SSH_PORT="2020"              # Your pfSense SSH port
PFSENSE_USER="admin"
SSH_KEY="/etc/ssh/pfsense_automation" # Path to SSH key

# Protected IPs - these can never be quarantined
PROTECTED_IPS=("10.10.0.1" "10.10.0.27" "10.10.0.35" "10.10.0.167" "127.0.0.1")

LOG_FILE="/var/log/pfsense-quarantine.log"

# =============================================================================
# FUNCTIONS
# =============================================================================

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"
    echo "$1"
}

is_protected() {
    local ip="$1"
    for protected in "${PROTECTED_IPS[@]}"; do
        if [[ "$ip" == "$protected" ]]; then
            return 0
        fi
    done
    return 1
}

validate_ip() {
    local ip="$1"
    if [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        return 0
    fi
    return 1
}

ssh_command() {
    ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no -o ConnectTimeout=10 \
        -p "$PFSENSE_SSH_PORT" "${PFSENSE_USER}@${PFSENSE_HOST}" "$1" 2>/dev/null
}

# =============================================================================
# MAIN
# =============================================================================

ACTION="$1"
IP="$2"
REASON="${3:-Manual quarantine}"

case "$ACTION" in
    block)
        if [[ -z "$IP" ]]; then
            echo '{"status":"error","message":"No IP provided"}'
            exit 1
        fi
        
        if ! validate_ip "$IP"; then
            echo '{"status":"error","message":"Invalid IP format"}'
            exit 1
        fi
        
        if is_protected "$IP"; then
            log "BLOCKED: Attempt to quarantine protected IP $IP"
            echo '{"status":"error","message":"Cannot quarantine protected IP"}'
            exit 1
        fi
        
        log "Quarantining IP: $IP - Reason: $REASON"
        
        # Add to pfSense quarantine table
        result=$(ssh_command "pfctl -t quarantine -T add $IP")
        
        if [[ $? -eq 0 ]]; then
            log "SUCCESS: $IP added to quarantine"
            echo "{\"status\":\"success\",\"action\":\"blocked\",\"ip\":\"$IP\",\"message\":\"IP quarantined\"}"
        else
            log "FAILED: Could not quarantine $IP"
            echo "{\"status\":\"error\",\"action\":\"blocked\",\"ip\":\"$IP\",\"message\":\"Failed to quarantine\"}"
            exit 1
        fi
        ;;
        
    unblock)
        if [[ -z "$IP" ]]; then
            echo '{"status":"error","message":"No IP provided"}'
            exit 1
        fi
        
        if ! validate_ip "$IP"; then
            echo '{"status":"error","message":"Invalid IP format"}'
            exit 1
        fi
        
        log "Removing IP from quarantine: $IP"
        
        # Remove from pfSense quarantine table
        result=$(ssh_command "pfctl -t quarantine -T delete $IP")
        
        if [[ $? -eq 0 ]]; then
            log "SUCCESS: $IP removed from quarantine"
            echo "{\"status\":\"success\",\"action\":\"unblocked\",\"ip\":\"$IP\",\"message\":\"IP released\"}"
        else
            log "FAILED: Could not release $IP"
            echo "{\"status\":\"error\",\"action\":\"unblocked\",\"ip\":\"$IP\",\"message\":\"Failed to release\"}"
            exit 1
        fi
        ;;
        
    list)
        log "Listing quarantined IPs"
        result=$(ssh_command "pfctl -t quarantine -T show")
        echo "$result"
        ;;
        
    *)
        echo "Usage: $0 block|unblock|list [ip] [reason]"
        echo ""
        echo "Commands:"
        echo "  block <ip> [reason]  - Quarantine an IP"
        echo "  unblock <ip>         - Release an IP from quarantine"
        echo "  list                 - Show all quarantined IPs"
        exit 1
        ;;
esac
