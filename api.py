import asyncio
import json
import threading
from typing import Dict, Any, List, Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from core.capture import PacketCaptureEngine

app = FastAPI(title="Sentinel Network Security API")

# Enable CORS for React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Adjust in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global State
class SnifferState:
    def __init__(self):
        self.sniffer = None
        self.sniff_thread = None
        self.is_running = False
        self.active_connections: List[WebSocket] = []
        self.loop = None
        
        # Stats
        self.total_packets = 0
        self.tcp_traffic = 0
        self.udp_traffic = 0
        self.alerts_count = 0

state = SnifferState()

@app.on_event("startup")
async def startup_event():
    state.loop = asyncio.get_running_loop()

async def broadcast_message(message: dict):
    # Remove dead connections
    dead_connections = []
    for connection in state.active_connections:
        try:
            await connection.send_text(json.dumps(message))
        except Exception:
            dead_connections.append(connection)
            
    for connection in dead_connections:
        if connection in state.active_connections:
            state.active_connections.remove(connection)

def packet_callback(packet_info: Dict[str, Any], warnings: List[str], stats: Dict[str, int]):
    """Called by the sniffer thread when a packet is intercepted"""
    if not state.is_running:
        return
        
    state.total_packets = stats.get("total", 0)
    state.tcp_traffic = stats.get("TCP", 0)
    state.udp_traffic = stats.get("UDP", 0)
    
    if warnings:
        state.alerts_count += len(warnings)
        
    message = {
        "type": "packet",
        "info": packet_info,
        "warnings": warnings,
        "stats": {
            "total": state.total_packets,
            "tcp": state.tcp_traffic,
            "udp": state.udp_traffic,
            "alerts": state.alerts_count
        }
    }
    
    # Schedule broadcast on the main event loop
    if state.loop and state.active_connections:
        asyncio.run_coroutine_threadsafe(broadcast_message(message), state.loop)

class CaptureConfig(BaseModel):
    protocol: str = "ALL"
    port: Optional[int] = None

@app.post("/api/start")
async def start_capture(config: CaptureConfig):
    if state.is_running:
        return {"status": "error", "message": "Capture is already running"}
        
    protocol_filter = config.protocol if config.protocol != "ALL" else None
    
    state.sniffer = PacketCaptureEngine(
        log_file='api_packets.log',
        protocol_filter=protocol_filter,
        port_filter=config.port,
        on_packet_callback=packet_callback
    )
    
    state.is_running = True
    
    def run_sniffer():
        try:
            state.sniffer.start_sniffing()
        except Exception as e:
            print(f"Sniffer error: {e}")
            state.is_running = False
            
    state.sniff_thread = threading.Thread(target=run_sniffer, daemon=True)
    state.sniff_thread.start()
    
    return {"status": "success", "message": "Capture started"}

@app.post("/api/stop")
async def stop_capture():
    if not state.is_running or not state.sniffer:
        return {"status": "error", "message": "Capture is not running"}
        
    state.sniffer.stop_sniffing()
    state.is_running = False
    return {"status": "success", "message": "Capture stopped"}

@app.get("/api/status")
async def get_status():
    return {
        "is_running": state.is_running,
        "stats": {
            "total": state.total_packets,
            "tcp": state.tcp_traffic,
            "udp": state.udp_traffic,
            "alerts": state.alerts_count
        }
    }

@app.websocket("/ws/traffic")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    state.active_connections.append(websocket)
    try:
        while True:
            # Keep connection open
            await websocket.receive_text()
    except WebSocketDisconnect:
        if websocket in state.active_connections:
            state.active_connections.remove(websocket)
