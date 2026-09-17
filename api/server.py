import asyncio
import os
import time
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

import config
from core.threat_engine import ThreatEngine
from core.firewall_manager import FirewallManager
from api.websocket_manager import WebSocketManager

class ManualBlockRequest(BaseModel):
    ip: str
    reason: str = "Manual SOC Admin Block"
    ttl_seconds: int = config.DEFAULT_BAN_TTL_SECONDS

class ManualUnblockRequest(BaseModel):
    ip: str

def create_app(threat_engine: ThreatEngine, firewall_mgr: FirewallManager) -> FastAPI:
    app = FastAPI(
        title=f"{config.PROJECT_NAME} SOC API",
        version=config.VERSION,
        description="Autonomous Security Monitoring & Automated IPS API Interface"
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    ws_manager = WebSocketManager()

    # Network Packet Capture Middleware (intercepts & registers incoming traffic)
    @app.middleware("http")
    async def capture_request_middleware(request: Request, call_next):
        client_ip = request.client.host if request.client else "127.0.0.1"
        dns_query = request.headers.get("X-DNS-Query") or request.headers.get("Host", "").split(":")[0]

        # Extract flags or protocol hints
        meta = {
            "timestamp": time.time(),
            "src_ip": client_ip,
            "dst_ip": request.url.hostname or "127.0.0.1",
            "src_port": request.client.port if request.client else 50000,
            "dst_port": request.url.port or config.API_PORT,
            "protocol": "TCP",
            "tcp_flags": request.headers.get("X-TCP-Flags", "PA"),
            "payload_len": len(request.url.path),
            "dns_query": dns_query if ("exfiltration" in dns_query or "demo" in dns_query) else None,
            "dns_type": "1"
        }

        # Process packet in threat engine
        threat_engine.process_packet_meta(meta)

        response = await call_next(request)
        return response

    # Register ThreatEngine WebSocket Callback bridge
    loop = asyncio.get_event_loop() if asyncio._get_running_loop() else None

    def sync_ws_broadcast(message: dict):
        try:
            loop_to_use = asyncio.get_event_loop()
            if loop_to_use.is_running():
                asyncio.run_coroutine_threadsafe(ws_manager.broadcast_json(message), loop_to_use)
        except Exception:
            pass

    threat_engine.set_websocket_callback(sync_ws_broadcast)

    # API Endpoints
    @app.get("/api/stats")
    def get_stats():
        return {
            "system": config.PROJECT_NAME,
            "version": config.VERSION,
            "platform": "LINUX" if config.IS_LINUX else "WINDOWS (DRY-RUN)",
            "stats": threat_engine.get_stats_summary()
        }

    @app.get("/api/alerts")
    def get_alerts(limit: int = 50):
        return threat_engine.get_recent_alerts(limit=limit)

    @app.get("/api/firewall/bans")
    def get_firewall_bans():
        return firewall_mgr.get_active_bans()

    @app.post("/api/firewall/block")
    def manual_block(req: ManualBlockRequest):
        success = firewall_mgr.block_ip(req.ip, req.reason, req.ttl_seconds)
        if not success:
            raise HTTPException(status_code=400, detail="Failed to block IP or IP is Whitelisted.")
        return {"status": "success", "message": f"IP {req.ip} successfully blocked."}

    @app.post("/api/firewall/unblock")
    def manual_unblock(req: ManualUnblockRequest):
        success = firewall_mgr.unblock_ip(req.ip)
        if not success:
            raise HTTPException(status_code=404, detail="IP was not found in active bans list.")
        return {"status": "success", "message": f"IP {req.ip} successfully unblocked."}

    @app.websocket("/ws/live")
    async def websocket_endpoint(websocket: WebSocket):
        await ws_manager.connect(websocket)
        try:
            await websocket.send_json({
                "event": "CONNECTED",
                "message": "Connected to AegisNet Sentinel Live Threat Feed",
                "stats": threat_engine.get_stats_summary(),
                "recent_alerts": threat_engine.get_recent_alerts(10)
            })
            while True:
                data = await websocket.receive_text()
        except WebSocketDisconnect:
            ws_manager.disconnect(websocket)
        except Exception:
            ws_manager.disconnect(websocket)

    # Mount static dashboard frontend
    if os.path.exists(config.WEB_UI_DIR):
        app.mount("/", StaticFiles(directory=config.WEB_UI_DIR, html=True), name="static")

    return app
