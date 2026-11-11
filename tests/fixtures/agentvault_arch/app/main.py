"""FastAPI surface: HTTP chat, websocket, SQL, and code-exec routes."""
from __future__ import annotations

from fastapi import FastAPI, WebSocket
from pydantic import BaseModel

from app.intake import accept_user_message
from app.sql_tool import run_query
from app.code_tool import run_code

app = FastAPI(title="AgentVault")


class ChatRequest(BaseModel):
    message: str


@app.post("/api/chat")
async def chat(body: ChatRequest):
    return {"response": accept_user_message(body.message)}


@app.websocket("/ws/chat")
async def websocket_chat(websocket: WebSocket):
    await websocket.accept()
    data = await websocket.receive_json()
    return accept_user_message(data.get("message", ""))


@app.post("/api/db-query")
async def db_query(body: ChatRequest):
    return {"rows": run_query(body.message)}


@app.post("/api/run-code")
async def run_user_code(body: ChatRequest):
    return {"out": run_code(body.message)}
