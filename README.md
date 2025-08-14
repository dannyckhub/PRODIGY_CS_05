# PRODIGY_CS_05
Network Packet Analyzer
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from datetime import datetime

# Log file
log_file = "danny_sniffer_log.txt"

# Show heading
print("=" * 60)
print("🕵️‍♂️  DANNY'S PACKET SNIFFER  📡")
print("Tracking packets clearly, cleanly, and with a smile 😎")
print("=" * 60 + "\n")
print("📶 Sniffing started... Press Ctrl + C to stop.\n")

# Save to log file
def log_to_file(text):
    with open(log_file, "a") as f:
        f.write(text + "\n")

# Handle each packet
def process_packet(packet):
    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        time = datetime.now().strftime("%H:%M:%S")
        proto = "UNKNOWN"
        sport = "-"
        dport = "-"

        if packet.haslayer(TCP):
            proto = "TCP"
            sport = packet[TCP].sport
            dport = packet[TCP].dport
        elif packet.haslayer(UDP):
            proto = "UDP"
            sport = packet[UDP].sport
            dport = packet[UDP].dport
        elif packet.haslayer(ICMP):
            proto = "ICMP"

        line = f"[{time}] {src}:{sport} {dst}:{dport} | {proto}"
        print(line)
        log_to_file(line)

        if packet.haslayer(Raw):
            try:
                payload = packet[Raw].load.decode(errors="ignore").strip()
                if payload:
                    payload_line = f"    Payload: {payload}"
                    print(payload_line)
                    log_to_file(payload_line)
            except:
                pass


sniff(prn=process_packet, store=False)
