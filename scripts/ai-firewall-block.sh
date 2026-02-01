#!/bin/sh
# AI-Enhanced Firewall Block Script for Wazuh Active Response
# Version 2.1 - Production Ready
# 
# Features:
# - Calls local LLM (LM Studio) for intelligent threat analysis
# - Automatic failsafe when AI is unreachable
# - Configurable block durations based on severity
# - Sensitive port detection
# - Comprehensive logging
#
# Requirements:
# - jq installed on pfSense: pkg install -y jq
# - LM Studio running with API server enabled
# - Wazuh agent configured with active response

# ============================================
# CONFIGURATION - MODIFY THESE VALUES
# ============================================

# LM Studio API endpoint (your Mac/AI server)
AI_URL="http://10.10.0.136:1234/v1/chat/completions"
AI_MODEL="qwen/qwen3-14b"

# Log files
LOG="/var/ossec/logs/active-responses.log"
AILOG="/var/ossec/logs/ai-decisions.log"

# Block durations (seconds)
SHORT=300    # 5 minutes  - Medium severity (Level 7-9)
MEDIUM=900   # 15 minutes - High severity (Level 10-11)
LONG=3600    # 1 hour     - Critical severity (Level 12-15)

# ============================================
# FUNCTIONS
# ============================================

# Logging functions
log_msg() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG"
}

log_ai() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$AILOG"
}

# Block IP using pfSense's snort2c table
do_block() {
    IP=$1
    DUR=$2
    REASON=$3
    
    /sbin/pfctl -t snort2c -T add "$IP" 2>/dev/null
    log_msg "BLOCKED: $IP for ${DUR}s - $REASON"
    log_ai "ACTION: BLOCK | IP: $IP | Duration: ${DUR}s | Reason: $REASON"
    
    # Schedule automatic unblock
    if [ "$DUR" -gt 0 ]; then
        (sleep "$DUR" && /sbin/pfctl -t snort2c -T delete "$IP" && \
         echo "$(date '+%Y-%m-%d %H:%M:%S') - UNBLOCKED: $IP after ${DUR}s" >> "$LOG") &
    fi
}

# Read and parse Wazuh alert input
read INPUT
DECODED=$(echo "$INPUT" | base64 -d 2>/dev/null || echo "$INPUT")

# Extract alert fields using jq
SRCIP=$(echo "$DECODED" | /usr/local/bin/jq -r '.parameters.alert.data.srcip // .parameters.srcip // "unknown"' 2>/dev/null)
RULEID=$(echo "$DECODED" | /usr/local/bin/jq -r '.parameters.alert.rule.id // "0"' 2>/dev/null)
LEVEL=$(echo "$DECODED" | /usr/local/bin/jq -r '.parameters.alert.rule.level // 0' 2>/dev/null)
DESC=$(echo "$DECODED" | /usr/local/bin/jq -r '.parameters.alert.rule.description // "unknown"' 2>/dev/null | tr -d '\n\r"')
DSTPORT=$(echo "$DECODED" | /usr/local/bin/jq -r '.parameters.alert.data.dstport // "unknown"' 2>/dev/null)

# Call AI for threat analysis
call_ai() {
    # Sanitize description - remove problematic characters
    SAFE_DESC=$(echo "$DESC" | tr -d '"\\{}[]' | tr '\n\r\t' ' ' | cut -c1-60)
    
    # Write JSON payload to temp file (avoids shell escaping issues)
    TMPJSON="/tmp/ai_payload_$$"
    cat > "$TMPJSON" << JSONEOF
{"model":"$AI_MODEL","messages":[{"role":"system","content":"You are a firewall analyst. Follow blocking rules EXACTLY. Output only valid JSON."},{"role":"user","content":"/no_think IP:$SRCIP Level:$LEVEL Port:$DSTPORT Desc:$SAFE_DESC. BLOCKING RULES: If level is 12 to 15 then block=true duration=1hour. If level is 10 to 11 then block=true duration=15min. If level is 7 to 9 then block=true duration=5min. If level is 0 to 6 then block=false. OUTPUT FORMAT: {\"block\":true,\"duration\":\"5min\",\"reason\":\"level X is Y severity\",\"confidence\":0.9}"}],"temperature":0.0,"max_tokens":120}
JSONEOF
    
    # Make API call
    RESP=$(curl -s -m 15 -X POST "$AI_URL" \
        -H "Content-Type: application/json" \
        -d @"$TMPJSON" 2>/dev/null)
    
    rm -f "$TMPJSON"
    
    # Check if response is empty (AI unreachable)
    if [ -z "$RESP" ]; then
        echo "UNREACHABLE"
        return 1
    fi
    
    # Check for API error
    ERRMSG=$(echo "$RESP" | /usr/local/bin/jq -r '.error.message // empty' 2>/dev/null)
    if [ -n "$ERRMSG" ]; then
        log_ai "AI ERROR: $ERRMSG"
        echo "ERROR"
        return 1
    fi
    
    # Extract content from response
    CONTENT=$(echo "$RESP" | /usr/local/bin/jq -r '.choices[0].message.content // "ERROR"' 2>/dev/null)
    if [ "$CONTENT" = "ERROR" ] || [ -z "$CONTENT" ]; then
        echo "ERROR"
        return 1
    fi
    
    # Clean response - remove thinking tags, markdown, extract JSON
    CLEAN=$(echo "$CONTENT" | sed 's/<think>.*<\/think>//g' | sed 's/```json//g' | sed 's/```//g' | tr -d '\n\r' | sed 's/.*{/{/' | sed 's/}.*/}/')
    echo "$CLEAN"
    return 0
}

# Fallback decision when AI is unavailable
fallback_block() {
    log_ai "AI down, using fallback"
    log_msg "$(date '+%Y-%m-%d %H:%M:%S') - AI down, using fallback"
    
    # Check for sensitive ports (get longer blocks)
    SENSITIVE=0
    case "$DSTPORT" in
        22|23|3389|445|3306|5432|1433|27017)
            SENSITIVE=1
            ;;
    esac
    
    # Apply rule-based blocking
    if [ "$LEVEL" -ge 12 ]; then
        # Critical - 1 hour
        do_block "$SRCIP" "$LONG" "FALLBACK:Critical(L$LEVEL)"
    elif [ "$LEVEL" -ge 10 ]; then
        # High - 15min, or 1hr if sensitive port
        if [ "$SENSITIVE" -eq 1 ]; then
            do_block "$SRCIP" "$LONG" "FALLBACK:High(L$LEVEL)+SensitivePort($DSTPORT)"
        else
            do_block "$SRCIP" "$MEDIUM" "FALLBACK:High(L$LEVEL)"
        fi
    elif [ "$LEVEL" -ge 7 ]; then
        # Medium - 5min, or 15min if sensitive port
        if [ "$SENSITIVE" -eq 1 ]; then
            do_block "$SRCIP" "$MEDIUM" "FALLBACK:Medium(L$LEVEL)+SensitivePort($DSTPORT)"
        else
            do_block "$SRCIP" "$SHORT" "FALLBACK:Medium(L$LEVEL)"
        fi
    else
        # Low - log only
        log_ai "NO BLOCK: Low severity (L$LEVEL) - $SRCIP"
        log_msg "NO BLOCK: Low severity (L$LEVEL) - $SRCIP"
    fi
}

# Parse duration string to seconds
parse_duration() {
    case "$1" in
        "5min"|"5 min"|"5minutes"|"5 minutes")
            echo $SHORT
            ;;
        "15min"|"15 min"|"15minutes"|"15 minutes")
            echo $MEDIUM
            ;;
        "1hour"|"1 hour"|"60min"|"1hr")
            echo $LONG
            ;;
        *)
            echo $MEDIUM
            ;;
    esac
}

# ============================================
# MAIN EXECUTION
# ============================================

# Validate source IP
if [ "$SRCIP" = "unknown" ] || [ -z "$SRCIP" ]; then
    log_msg "ERROR: No source IP in alert"
    exit 1
fi

# Skip internal/private IPs
case "$SRCIP" in
    10.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[0-1].*|127.*)
        log_msg "SKIP: Internal IP $SRCIP"
        exit 0
        ;;
esac

log_ai "===== NEW ALERT ====="
log_ai "IP:$SRCIP | Rule:$RULEID | Level:$LEVEL | Port:$DSTPORT | Desc:$DESC"

# Try AI decision
AIRESP=$(call_ai)
AIRET=$?

# Check AI availability
if [ $AIRET -ne 0 ] || [ "$AIRESP" = "UNREACHABLE" ] || [ "$AIRESP" = "ERROR" ]; then
    log_ai "WARNING: AI unavailable ($AIRESP) - using fallback rules"
    fallback_block
    exit 0
fi

log_ai "AI Response: $AIRESP"

# Parse AI response
SHOULD_BLOCK=$(echo "$AIRESP" | /usr/local/bin/jq -r '.block // false' 2>/dev/null)
DURATION_STR=$(echo "$AIRESP" | /usr/local/bin/jq -r '.duration // "15min"' 2>/dev/null)
AI_REASON=$(echo "$AIRESP" | /usr/local/bin/jq -r '.reason // "AI decision"' 2>/dev/null)
CONFIDENCE=$(echo "$AIRESP" | /usr/local/bin/jq -r '.confidence // 0' 2>/dev/null)

log_ai "AI Decision: block=$SHOULD_BLOCK, duration=$DURATION_STR, confidence=$CONFIDENCE"

if [ "$SHOULD_BLOCK" = "true" ]; then
    DUR_SECS=$(parse_duration "$DURATION_STR")
    do_block "$SRCIP" "$DUR_SECS" "AI: $AI_REASON (conf:$CONFIDENCE)"
else
    log_ai "NO BLOCK: AI decided not to block - $AI_REASON"
    log_msg "AI decision: Do not block $SRCIP - $AI_REASON"
fi

exit 0
