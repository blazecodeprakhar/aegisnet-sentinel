import sys
import time
import signal
import uvicorn
import argparse
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

import config
from core.firewall_manager import FirewallManager
from core.threat_engine import ThreatEngine
from core.packet_capturer import PacketCapturer
from api.server import create_app

console = Console()

def print_banner():
    banner_text = f"""
[bold cyan]AEGISNET SENTINEL[/bold cyan] [bold white]v{config.VERSION}[/bold white]
[bold green]Autonomous NIDS & Automated Firewall IPS Engine[/bold green]
[dim]Operating System: {'KALI / LINUX (NATIVE IPTABLES)' if config.IS_LINUX else 'WINDOWS (DRY-RUN IPS MODE)'}[/dim]
    """
    console.print(Panel(banner_text, expand=False, border_style="cyan"))

def main():
    parser = argparse.ArgumentParser(description="AegisNet Sentinel - Security Monitoring & Automated IPS")
    parser.add_argument("--host", type=str, default=config.API_HOST, help="API and Dashboard host IP")
    parser.add_argument("--port", type=int, default=config.API_PORT, help="API and Dashboard port")
    parser.add_argument("--iface", type=str, default=config.SNIFF_INTERFACE, help="Network interface to sniff")
    
    args = parser.parse_args()

    print_banner()

    # Initialize Core Subsystems
    console.print("[bold yellow][*] Initializing Firewall Manager...[/bold yellow]")
    firewall_mgr = FirewallManager()

    console.print("[bold yellow][*] Initializing Threat Engine & Detectors...[/bold yellow]")
    threat_engine = ThreatEngine(firewall_mgr)

    console.print(f"[bold yellow][*] Initializing Network Packet Sniffer (Interface: {args.iface or 'Auto-Detect'})...[/bold yellow]")
    packet_capturer = PacketCapturer(threat_engine, interface=args.iface)

    # Start Packet Sniffer
    packet_capturer.start()

    # Build FastAPI Application
    app = create_app(threat_engine, firewall_mgr)

    table = Table(title="System Service Status", show_header=True, header_style="bold magenta")
    table.add_column("Component", style="cyan")
    table.add_column("Status", style="green")
    table.add_column("Endpoint / Location")

    table.add_row("SOC Dashboard UI", "ONLINE", f"http://{args.host}:{args.port}/")
    table.add_row("REST API Service", "ONLINE", f"http://{args.host}:{args.port}/api/stats")
    table.add_row("Live WS Feed", "ONLINE", f"ws://{args.host}:{args.port}/ws/live")
    table.add_row("Packet Capturer", "ACTIVE", f"Interface: {args.iface or 'Default Gateway'}")
    table.add_row("Firewall IPS Engine", "ACTIVE", "IPTables Native" if config.IS_LINUX else "Windows Dry-Run Mode")

    console.print(table)
    console.print("\n[bold green][+] AegisNet Sentinel is actively monitoring traffic. Press Ctrl+C to terminate.[/bold green]\n")

    def signal_handler(sig, frame):
        console.print("\n[bold red][!] Shutting down AegisNet Sentinel daemon...[/bold red]")
        packet_capturer.stop()
        firewall_mgr.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    # Run Uvicorn Web Server
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")

if __name__ == "__main__":
    main()
