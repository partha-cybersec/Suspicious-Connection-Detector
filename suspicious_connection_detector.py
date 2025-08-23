import psutil
import socket
import requests
from rich.console import Console
from rich.table import Table
from datetime import datetime
import time

console = Console()

# Trusted IPs or countries
trusted_countries = ["IN"]  # Change or add more country codes if needed
log_file = "suspicious_connections.log"

def get_ip_country(ip):
    try:
        res = requests.get(f"https://ipapi.co/{ip}/country/", timeout=2)
        if res.status_code == 200:
            return res.text.strip()
    except:
        return "Unknown"

def log_event(info):
    with open(log_file, "a") as f:
        f.write(info + "\n")

def get_active_connections():
    connections = []
    for conn in psutil.net_connections(kind='inet'):
        if conn.status == 'ESTABLISHED' and conn.raddr:
            try:
                proc = psutil.Process(conn.pid)
                proc_name = proc.name()
            except:
                proc_name = "Unknown"

            remote_ip = conn.raddr.ip
            remote_port = conn.raddr.port
            local_ip = conn.laddr.ip
            local_port = conn.laddr.port

            country = get_ip_country(remote_ip)
            suspicious = country not in trusted_countries

            connections.append({
                "pid": conn.pid,
                "proc_name": proc_name,
                "local": f"{local_ip}:{local_port}",
                "remote": f"{remote_ip}:{remote_port}",
                "country": country,
                "suspicious": suspicious
            })
    return connections

try:
    while True:
        console.clear()
        table = Table(title=f"🌐 Suspicious Connection Monitor — {datetime.now().strftime('%H:%M:%S')}")

        table.add_column("PID", style="cyan")
        table.add_column("Process", style="green")
        table.add_column("Local Address")
        table.add_column("Remote Address")
        table.add_column("Country")
        table.add_column("Flag", style="red")

        conns = get_active_connections()
        for conn in conns:
            flag = "⚠️ Suspicious" if conn["suspicious"] else ""
            if conn["suspicious"]:
                log_info = f"[{datetime.now()}] PID {conn['pid']} ({conn['proc_name']}) -> {conn['remote']} [{conn['country']}]"
                log_event(log_info)

            table.add_row(
                str(conn["pid"]),
                conn["proc_name"],
                conn["local"],
                conn["remote"],
                conn["country"],
                flag
            )

        console.print(table)
        time.sleep(5)

except KeyboardInterrupt:
    print("\n[!] Stopped by user.")
