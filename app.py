
from flask import Flask, jsonify, render_template, request, Response
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
import threading
import datetime
import os
import csv
import io
import json
import itertools
from collections import Counter, deque

app = Flask(__name__)

_lock       = threading.Lock()
packets_log = deque(maxlen=1000)          # thread-safe fixed-size buffer
stats       = {"total": 0, "tcp": 0, "udp": 0, "icmp": 0, "total_size": 0}
monitoring  = False
sniff_thread = None
_id_counter  = itertools.count(1)         # atomic-safe counter

PORT_SERVICES = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET",
    25: "SMTP",  53: "DNS",  67: "DHCP",  68: "DHCP",
    69: "TFTP",  80: "HTTP", 110: "POP3", 123: "NTP",
    143: "IMAP", 161: "SNMP", 194: "IRC", 443: "HTTPS",
    445: "SMB",  465: "SMTPS", 514: "SYSLOG", 587: "SMTP",
    993: "IMAPS", 995: "POP3S", 1080: "SOCKS",
    1194: "OpenVPN", 1433: "MSSQL", 1723: "PPTP",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC",  6379: "Redis", 6881: "BitTorrent",
    8080: "HTTP-ALT", 8443: "HTTPS-ALT", 27017: "MongoDB",
}

def get_service(pkt):
    port = None
    if pkt.haslayer(TCP):
        port = pkt[TCP].dport
    elif pkt.haslayer(UDP):
        port = pkt[UDP].dport
    if port and port in PORT_SERVICES:
        return PORT_SERVICES[port]
    if pkt.haslayer(ICMP):
        return "ICMP-ECHO"
    return "Unknown"

def process_packet(pkt):
    if not pkt.haslayer(IP):
        return

    pid  = next(_id_counter)
    now  = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
    src  = pkt[IP].src
    dst  = pkt[IP].dst
    size = len(pkt)
    service = get_service(pkt)
    flags = ""

    if pkt.haslayer(TCP):
        proto    = "TCP"
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
        # Decode TCP flags
        f = pkt[TCP].flags
        flag_map = [(0x02,"SYN"),(0x10,"ACK"),(0x01,"FIN"),(0x04,"RST"),(0x08,"PSH"),(0x20,"URG")]
        flags = " ".join(name for bit, name in flag_map if f & bit)
        proto_key = "tcp"
    elif pkt.haslayer(UDP):
        proto    = "UDP"
        src_port = pkt[UDP].sport
        dst_port = pkt[UDP].dport
        proto_key = "udp"
    elif pkt.haslayer(ICMP):
        proto    = "ICMP"
        src_port = 0
        dst_port = 0
        icmp_types = {0:"Echo Reply", 3:"Dest Unreachable", 8:"Echo Request",
                      11:"Time Exceeded", 5:"Redirect"}
        flags = icmp_types.get(pkt[ICMP].type, f"Type {pkt[ICMP].type}")
        proto_key = "icmp"
    else:
        return

    record = {
        "id":       pid,
        "time":     now,
        "src_ip":   src,
        "dst_ip":   dst,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": proto,
        "size":     size,
        "service":  service,
        "flags":    flags,
        "ttl":      pkt[IP].ttl,
    }

    with _lock:
        packets_log.append(record)
        stats["total"]      += 1
        stats[proto_key]    += 1
        stats["total_size"] += size

def sniff_packets():
    sniff(
        filter="ip",
        prn=process_packet,
        store=False,
        stop_filter=lambda _: not monitoring,
    )

@app.route("/monitor/begin", methods=["POST"])   
def start():
    global monitoring, sniff_thread, packets_log, stats
    if monitoring:
        return jsonify({"status": "already running"})

    with _lock:
        packets_log = deque(maxlen=1000)
        stats.update({"total": 0, "tcp": 0, "udp": 0, "icmp": 0, "total_size": 0})
        # Reset counter
        global _id_counter
        _id_counter = itertools.count(1)

    monitoring   = True
    sniff_thread = threading.Thread(target=sniff_packets, daemon=True)
    sniff_thread.start()
    return jsonify({"status": "started"})

@app.route("/monitor/halt", methods=["POST"])    # was: /api/stop
def stop():
    global monitoring
    monitoring = False
    return jsonify({"status": "stopped"})

@app.route("/traffic/fetch", methods=["GET"])    # was: /api/packets
def get_packets():
    proto_filter = request.args.get("protocol", "ALL").upper()
    src_filter   = request.args.get("src_ip", "").strip()
    dst_filter   = request.args.get("dst_ip", "").strip()
    since_id     = int(request.args.get("since_id", 0))

    with _lock:
        snapshot  = list(packets_log)
        snap_stats = dict(stats)

    filtered = snapshot
    if proto_filter != "ALL":
        filtered = [p for p in filtered if p["protocol"] == proto_filter]
    if src_filter:
        filtered = [p for p in filtered if src_filter in p["src_ip"]]
    if dst_filter:
        filtered = [p for p in filtered if dst_filter in p["dst_ip"]]

    # Only send packets newer than since_id for efficient polling
    new_packets = [p for p in filtered if p["id"] > since_id]

    source_counts = Counter(p["src_ip"] for p in snapshot)
    top_sources   = [{"ip": ip, "count": c} for ip, c in source_counts.most_common(5)]

    total = snap_stats["total"]
    avg_size = round(snap_stats["total_size"] / total, 1) if total else 0

    return jsonify({
        "monitoring": monitoring,
        "packets":    new_packets[-100:],          
        "all_count":  len(filtered),
        "stats": {
            "total":       total,
            "tcp":         snap_stats["tcp"],
            "udp":         snap_stats["udp"],
            "icmp":        snap_stats["icmp"],
            "avg_size":    avg_size,
            "top_sources": top_sources,
        }
    })

@app.route("/system/status")                    
def status():
    with _lock:
        return jsonify({"monitoring": monitoring, "total": stats["total"]})

@app.route("/export/csv")                        
def export_csv():
    with _lock:
        snapshot = list(packets_log)
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=[
        "id","time","src_ip","src_port","dst_ip","dst_port","protocol","size","service","flags","ttl"
    ])
    writer.writeheader()
    writer.writerows(snapshot)
    fname = f"packets_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    return Response(output.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": f"attachment; filename={fname}"})

@app.route("/export/json")                      
def export_json():
    with _lock:
        snapshot   = list(packets_log)
        snap_stats = dict(stats)
    payload = {
        "exported_at": datetime.datetime.now().isoformat(),
        "stats": snap_stats,
        "packets": snapshot
    }
    fname = f"packets_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    return Response(json.dumps(payload, indent=2), mimetype="application/json",
                    headers={"Content-Disposition": f"attachment; filename={fname}"})

@app.route("/live-traffic")    
def index():
    return render_template("index.html")

if __name__ == "__main__":
    is_admin = False
    try:
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    except (AttributeError, ImportError):
        if hasattr(os, 'geteuid'):
            is_admin = os.geteuid() == 0
        else:
            is_admin = True  
    
    if not is_admin:
        print("⚠  WARNING: Not running as Administrator. Packet capture may fail.")
        print("   Please run as Administrator: Right-click PowerShell/Terminal → Run as Administrator")
    else:
        print("✓ Running with administrator privileges")
    
    print("=" * 55)
    print("  NetView — Real-Time Network Traffic Analyzer")
    print("  Open: http://127.0.0.1:4500/live-traffic") 
    print("=" * 55)
    app.run(host="0.0.0.0", port=4500, debug=False)