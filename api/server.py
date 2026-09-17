import asyncio
import os
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
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

    # Register ThreatEngine WebSocket Callback bridge
    loop = asyncio.get_event_loop() if asyncio._get_running_loop() else None

    def sync_ws_broadcast(message: dict):
        try:
            # Safely schedule async broadcast from thread
            loop_to_use = asyncio.get_event_loop()
            if loop_to_use.is_running():
                asyncio.run_coroutine_threadsafe(ws_manager.broadcast_json(message), loop_to_use)
        except Exception as e:
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
            # Send initial state greeting
            await websocket.send_json({
                "event": "CONNECTED",
                "message": "Connected to AegisNet Sentinel Live Threat Feed",
                "stats": threat_engine.get_stats_summary(),
                "recent_alerts": threat_engine.get_recent_alerts(10)
            })
            while True:
                # Keep socket alive
                data = await websocket.receive_text()
        except WebSocketDisconnect:
            ws_manager.disconnect(websocket)
        except Exception:
            ws_manager.disconnect(websocket)

    # Mount static dashboard frontend
    if os.path.exists(config.WEB_UI_DIR):
        app.mount("/", StaticFiles(directory=config.WEB_UI_DIR, html=True), name="static")

    return app
