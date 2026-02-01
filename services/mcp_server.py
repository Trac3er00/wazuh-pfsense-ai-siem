#!/usr/bin/env python3
"""
Wazuh MCP Server - Bridges Wazuh SIEM with AI Assistants
REST API and web interface for SIEM interaction

Location: /opt/wazuh-mcp/server.py
Service: wazuh-mcp (port 8081)

Author: @Trac3er00
"""

import os
import json
import urllib3
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# =============================================================================
# CONFIGURATION
# =============================================================================

WAZUH_API_URL = "https://127.0.0.1:55000"
WAZUH_USER = "wazuh-wui"
WAZUH_PASS = "YOUR_WAZUH_API_PASSWORD"  # Get from /usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml
THREAT_HUNTER_URL = "http://127.0.0.1:8080"

# =============================================================================
# FASTAPI APP
# =============================================================================

app = FastAPI(title="Wazuh MCP Server", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

_token_cache = {"token": None, "expires": None}

# =============================================================================
# AUTH FUNCTIONS
# =============================================================================

async def get_wazuh_token() -> str:
    """Get authentication token from Wazuh API"""
    global _token_cache
    if _token_cache["token"] and _token_cache["expires"] and datetime.now() < _token_cache["expires"]:
        return _token_cache["token"]
    async with httpx.AsyncClient(verify=False) as client:
        response = await client.post(f"{WAZUH_API_URL}/security/user/authenticate", auth=(WAZUH_USER, WAZUH_PASS))
        if response.status_code == 200:
            data = response.json()
            _token_cache["token"] = data["data"]["token"]
            _token_cache["expires"] = datetime.now() + timedelta(minutes=15)
            return _token_cache["token"]
        else:
            raise HTTPException(status_code=401, detail="Failed to authenticate with Wazuh API")

async def wazuh_api_request(endpoint: str, method: str = "GET", params: dict = None) -> dict:
    """Make authenticated request to Wazuh API"""
    token = await get_wazuh_token()
    headers = {"Authorization": f"Bearer {token}"}
    async with httpx.AsyncClient(verify=False) as client:
        if method == "GET":
            response = await client.get(f"{WAZUH_API_URL}{endpoint}", headers=headers, params=params)
        elif method == "POST":
            response = await client.post(f"{WAZUH_API_URL}{endpoint}", headers=headers, json=params)
        else:
            raise ValueError(f"Unsupported method: {method}")
        return response.json()

# =============================================================================
# MODELS
# =============================================================================

class QueryRequest(BaseModel):
    question: str
    hours: int = 24
    max_results: int = 10

# =============================================================================
# API ENDPOINTS
# =============================================================================

@app.get("/")
async def root():
    """Server status and available tools"""
    return {"service": "Wazuh MCP Server", "status": "running", "version": "1.0.0",
            "tools": ["list_agents", "get_agent", "list_alerts", "get_alert_summary", "search_logs"]}

@app.get("/ui", response_class=HTMLResponse)
async def serve_ui():
    """Serve the chat web interface"""
    return """<!DOCTYPE html>
<html>
<head>
    <title>Wazuh AI Chat</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #1a1a2e; color: #eee; min-height: 100vh; }
        .container { max-width: 900px; margin: 0 auto; padding: 20px; }
        h1 { text-align: center; margin-bottom: 20px; color: #00d4ff; }
        .chat-box { background: #16213e; border-radius: 10px; padding: 20px; min-height: 500px; max-height: 600px; overflow-y: auto; margin-bottom: 20px; }
        .message { margin-bottom: 15px; padding: 12px 16px; border-radius: 8px; white-space: pre-wrap; }
        .user { background: #0f3460; margin-left: 50px; }
        .assistant { background: #1a1a2e; border: 1px solid #333; margin-right: 50px; }
        .input-area { display: flex; gap: 10px; }
        input { flex: 1; padding: 15px; border: none; border-radius: 8px; background: #16213e; color: #eee; font-size: 16px; }
        input:focus { outline: 2px solid #00d4ff; }
        button { padding: 15px 30px; background: #00d4ff; color: #000; border: none; border-radius: 8px; cursor: pointer; font-weight: bold; }
        button:hover { background: #00a8cc; }
        .tools { display: flex; gap: 10px; margin-bottom: 15px; flex-wrap: wrap; }
        .tool-btn { padding: 8px 15px; background: #0f3460; border: 1px solid #00d4ff; color: #00d4ff; border-radius: 5px; cursor: pointer; font-size: 12px; }
        .tool-btn:hover { background: #00d4ff; color: #000; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ Wazuh AI Security Assistant</h1>
        <div class="tools">
            <button class="tool-btn" onclick="quickQuery('List all agents')">📋 Agents</button>
            <button class="tool-btn" onclick="quickQuery('Show alert summary')">📊 Summary</button>
            <button class="tool-btn" onclick="quickQuery('Were there any SSH brute force attacks?')">🔐 SSH</button>
            <button class="tool-btn" onclick="quickQuery('Show blocked firewall connections')">🔥 Firewall</button>
            <button class="tool-btn" onclick="quickQuery('What DNS domains were blocked?')">🌐 DNS</button>
        </div>
        <div class="chat-box" id="chat"></div>
        <div class="input-area">
            <input type="text" id="input" placeholder="Ask about your security logs..." onkeypress="if(event.key==='Enter')sendMessage()">
            <button onclick="sendMessage()">Send</button>
        </div>
    </div>
    <script>
        const API = window.location.origin;
        const chat = document.getElementById('chat');
        const input = document.getElementById('input');
        function addMessage(text, isUser) {
            const div = document.createElement('div');
            div.className = 'message ' + (isUser ? 'user' : 'assistant');
            if (typeof text === 'object') text = JSON.stringify(text, null, 2);
            div.textContent = text;
            chat.appendChild(div);
            chat.scrollTop = chat.scrollHeight;
        }
        async function sendMessage() {
            const text = input.value.trim();
            if (!text) return;
            addMessage(text, true);
            input.value = '';
            input.disabled = true;
            try {
                const res = await fetch(API + '/chat', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({question: text, hours: 24, max_results: 15})
                });
                const data = await res.json();
                addMessage(data.answer || JSON.stringify(data, null, 2), false);
            } catch(e) {
                addMessage('Error: ' + e.message, false);
            }
            input.disabled = false;
            input.focus();
        }
        function quickQuery(q) { input.value = q; sendMessage(); }
        addMessage('Welcome! Ask me about your security logs.\\n\\nExamples:\\n• Were there any SSH attacks?\\n• Show me blocked DNS queries\\n• List all agents', false);
    </script>
</body>
</html>"""

@app.get("/tools")
async def list_tools():
    """List all available MCP tools"""
    return {
        "tools": [
            {"name": "list_agents", "description": "List all Wazuh agents with their status and IP addresses"},
            {"name": "get_agent", "description": "Get detailed information about a specific agent"},
            {"name": "list_alerts", "description": "List recent security alerts"},
            {"name": "get_alert_summary", "description": "Get a summary of alerts by category, level, and agent"},
            {"name": "search_logs", "description": "Search logs using natural language query via AI Threat Hunter"},
        ]
    }

@app.get("/agents")
async def list_agents(status: Optional[str] = None):
    """List all Wazuh agents"""
    params = {"status": status} if status else {}
    result = await wazuh_api_request("/agents", params=params)
    agents = [{"id": a.get("id"), "name": a.get("name"), "ip": a.get("ip"), "status": a.get("status"),
               "os": a.get("os", {}).get("name", "Unknown")} for a in result.get("data", {}).get("affected_items", [])]
    return {"agents": agents, "total": len(agents)}

@app.get("/agents/{agent_id}")
async def get_agent(agent_id: str):
    """Get detailed info for specific agent"""
    result = await wazuh_api_request(f"/agents?agents_list={agent_id}")
    if result.get("data", {}).get("affected_items"):
        return {"agent": result["data"]["affected_items"][0]}
    else:
        raise HTTPException(status_code=404, detail=f"Agent {agent_id} not found")

@app.get("/alerts")
async def list_alerts(limit: int = 20, level: Optional[int] = None):
    """List recent security alerts"""
    params = {"limit": limit, "sort": "-timestamp"}
    if level:
        params["q"] = f"rule.level>={level}"
    result = await wazuh_api_request("/alerts", params=params)
    alerts = []
    for alert in result.get("data", {}).get("affected_items", []):
        alerts.append({
            "id": alert.get("id"),
            "timestamp": alert.get("timestamp"),
            "rule": {"id": alert.get("rule", {}).get("id"), "level": alert.get("rule", {}).get("level"),
                     "description": alert.get("rule", {}).get("description")},
            "agent": alert.get("agent", {}).get("name"),
            "srcip": alert.get("data", {}).get("srcip")
        })
    return {"alerts": alerts, "total": len(alerts)}

@app.get("/alerts/summary")
async def get_alert_summary():
    """Get alert summary statistics"""
    result = await wazuh_api_request("/alerts", params={"limit": 500})
    alerts = result.get("data", {}).get("affected_items", [])
    by_level, by_agent = {}, {}
    for a in alerts:
        lvl = a.get("rule", {}).get("level", 0)
        agent = a.get("agent", {}).get("name", "Unknown")
        by_level[lvl] = by_level.get(lvl, 0) + 1
        by_agent[agent] = by_agent.get(agent, 0) + 1
    return {"total": len(alerts), "by_level": dict(sorted(by_level.items(), reverse=True)),
            "by_agent": dict(sorted(by_agent.items(), key=lambda x: x[1], reverse=True)[:10])}

@app.post("/search")
async def search_logs(request: QueryRequest):
    """Search logs using natural language via Threat Hunter"""
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(f"{THREAT_HUNTER_URL}/query",
                json={"question": request.question, "hours": request.hours, "max_results": request.max_results}, timeout=120)
            return response.json()
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Threat Hunter error: {str(e)}")

@app.post("/chat")
async def chat(request: QueryRequest):
    """Main chat endpoint - interprets questions and routes to appropriate tool"""
    question = request.question.lower()
    if "agent" in question and ("list" in question or "show" in question or "all" in question):
        return await list_agents()
    elif "alert" in question and "summary" in question:
        return await get_alert_summary()
    else:
        return await search_logs(request)

# =============================================================================
# MAIN
# =============================================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8081)
