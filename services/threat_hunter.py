#!/usr/bin/env python3
"""
AI-Powered Threat Hunter for Wazuh
Query your security logs using natural language
Uses LMStudio + FAISS vector store for semantic search

Location: /var/ossec/integrations/threat_hunter.py
Service: wazuh-threat-hunter (port 8080)

Author: @Trac3er00
"""

import os
import json
import gzip
import glob
from datetime import datetime, timedelta
from typing import List, Dict, Optional
import requests

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Vector store imports
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_community.vectorstores import FAISS
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_core.documents import Document

# =============================================================================
# CONFIGURATION
# =============================================================================

LMSTUDIO_URL = "http://10.10.0.136:1234/v1/chat/completions"  # Your LMStudio server
LMSTUDIO_MODEL = "qwen/qwen3-14b"  # Model name
ARCHIVES_PATH = "/var/ossec/logs/archives"
VECTOR_STORE_PATH = "/var/ossec/logs/threat_hunter_vectorstore"

# =============================================================================
# FASTAPI APP
# =============================================================================

app = FastAPI(title="Wazuh AI Threat Hunter", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global vector store
vector_store = None
embeddings = None
last_load_time = None

# =============================================================================
# MODELS
# =============================================================================

class QueryRequest(BaseModel):
    question: str
    hours: int = 24
    max_results: int = 20

class QueryResponse(BaseModel):
    answer: str
    relevant_logs: List[Dict]
    query_time: float
    logs_analyzed: int

# =============================================================================
# FUNCTIONS
# =============================================================================

def load_archives(hours: int = 24) -> List[Dict]:
    """Load archive logs from the specified time period"""
    logs = []
    cutoff_time = datetime.now() - timedelta(hours=hours)
    
    # Load current archives.json
    current_archive = os.path.join(ARCHIVES_PATH, "archives.json")
    if os.path.exists(current_archive):
        try:
            with open(current_archive, 'r') as f:
                for line in f:
                    try:
                        log = json.loads(line.strip())
                        logs.append(log)
                    except json.JSONDecodeError:
                        continue
        except Exception as e:
            print(f"Error reading current archive: {e}")
    
    # Load compressed archives if needed
    archive_pattern = os.path.join(ARCHIVES_PATH, "**/*.json.gz")
    for gz_file in glob.glob(archive_pattern, recursive=True):
        try:
            with gzip.open(gz_file, 'rt') as f:
                for line in f:
                    try:
                        log = json.loads(line.strip())
                        logs.append(log)
                    except json.JSONDecodeError:
                        continue
        except Exception as e:
            print(f"Error reading {gz_file}: {e}")
    
    return logs

def create_documents(logs: List[Dict]) -> List[Document]:
    """Convert logs to LangChain documents for vector store"""
    documents = []
    for log in logs:
        # Create a searchable text representation
        text_parts = []
        
        if 'rule' in log:
            rule = log['rule']
            text_parts.append(f"Rule: {rule.get('description', 'Unknown')}")
            text_parts.append(f"Level: {rule.get('level', 0)}")
            text_parts.append(f"Groups: {', '.join(rule.get('groups', []))}")
        
        if 'agent' in log:
            text_parts.append(f"Agent: {log['agent'].get('name', 'Unknown')}")
        
        if 'data' in log:
            data = log['data']
            if 'srcip' in data:
                text_parts.append(f"Source IP: {data['srcip']}")
            if 'dstip' in data:
                text_parts.append(f"Destination IP: {data['dstip']}")
            if 'srcuser' in data:
                text_parts.append(f"User: {data['srcuser']}")
        
        if 'full_log' in log:
            text_parts.append(f"Log: {log['full_log'][:500]}")
        
        if 'timestamp' in log:
            text_parts.append(f"Time: {log['timestamp']}")
        
        text = "\n".join(text_parts)
        
        doc = Document(
            page_content=text,
            metadata={
                "timestamp": log.get("timestamp", ""),
                "rule_id": log.get("rule", {}).get("id", ""),
                "rule_level": log.get("rule", {}).get("level", 0),
                "agent": log.get("agent", {}).get("name", ""),
                "full_log": log.get("full_log", "")[:1000]
            }
        )
        documents.append(doc)
    
    return documents

def init_vector_store(hours: int = 24):
    """Initialize or refresh the vector store"""
    global vector_store, embeddings, last_load_time
    
    print(f"Loading archives from last {hours} hours...")
    logs = load_archives(hours)
    print(f"Loaded {len(logs)} log entries")
    
    if not logs:
        return 0
    
    print("Creating documents...")
    documents = create_documents(logs)
    
    print("Initializing embeddings...")
    if embeddings is None:
        embeddings = HuggingFaceEmbeddings(
            model_name="sentence-transformers/all-MiniLM-L6-v2",
            model_kwargs={'device': 'cpu'}
        )
    
    print("Building vector store...")
    vector_store = FAISS.from_documents(documents, embeddings)
    last_load_time = datetime.now()
    
    print(f"Vector store ready with {len(documents)} documents")
    return len(documents)

def query_llm(question: str, context: str) -> str:
    """Query LMStudio with the question and relevant context"""
    prompt = f"""You are a cybersecurity analyst assistant. Based on the following security logs, answer the user's question.

SECURITY LOGS:
{context}

USER QUESTION: {question}

Provide a clear, concise analysis. Include:
1. Direct answer to the question
2. Key findings from the logs
3. Any security concerns or recommendations
4. Specific IPs, users, or events if relevant

If the logs don't contain relevant information, say so clearly."""

    try:
        response = requests.post(
            LMSTUDIO_URL,
            json={
                "model": LMSTUDIO_MODEL,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.3,
                "max_tokens": 1000
            },
            timeout=60
        )
        
        if response.status_code == 200:
            return response.json()["choices"][0]["message"]["content"]
        else:
            return f"Error querying LLM: {response.status_code}"
    except Exception as e:
        return f"Error connecting to LLM: {str(e)}"

# =============================================================================
# API ENDPOINTS
# =============================================================================

@app.on_event("startup")
async def startup_event():
    """Initialize vector store on startup"""
    print("Initializing Threat Hunter...")
    init_vector_store(hours=24)

@app.get("/")
async def root():
    return {
        "service": "Wazuh AI Threat Hunter",
        "status": "running",
        "vector_store_loaded": vector_store is not None,
        "last_load": last_load_time.isoformat() if last_load_time else None
    }

@app.post("/query", response_model=QueryResponse)
async def query_logs(request: QueryRequest):
    """Query security logs using natural language"""
    global vector_store
    
    start_time = datetime.now()
    
    # Refresh vector store if needed
    if vector_store is None or (last_load_time and datetime.now() - last_load_time > timedelta(hours=1)):
        init_vector_store(hours=request.hours)
    
    if vector_store is None:
        raise HTTPException(status_code=500, detail="Vector store not initialized")
    
    # Search for relevant logs
    docs = vector_store.similarity_search(request.question, k=request.max_results)
    
    # Build context from relevant logs
    context_parts = []
    relevant_logs = []
    for i, doc in enumerate(docs):
        context_parts.append(f"--- Log {i+1} ---\n{doc.page_content}")
        relevant_logs.append({
            "content": doc.page_content,
            "metadata": doc.metadata
        })
    
    context = "\n\n".join(context_parts)
    
    # Query LLM
    answer = query_llm(request.question, context)
    
    query_time = (datetime.now() - start_time).total_seconds()
    
    return QueryResponse(
        answer=answer,
        relevant_logs=relevant_logs,
        query_time=query_time,
        logs_analyzed=len(docs)
    )

@app.post("/refresh")
async def refresh_vector_store(hours: int = 24):
    """Manually refresh the vector store"""
    count = init_vector_store(hours=hours)
    return {"status": "refreshed", "documents_loaded": count}

@app.get("/stats")
async def get_stats():
    """Get threat hunter statistics"""
    return {
        "vector_store_loaded": vector_store is not None,
        "last_load_time": last_load_time.isoformat() if last_load_time else None,
        "document_count": vector_store.index.ntotal if vector_store else 0
    }

# =============================================================================
# MAIN
# =============================================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
