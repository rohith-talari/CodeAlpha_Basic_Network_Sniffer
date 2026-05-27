import sys
import logging
from datetime import datetime

# Checking for Scapy
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, conf
except ModuleNotFoundError:
    print("[!] Scapy is not installed.")
    print("Run: pip install scapy")
    sys.exit(1)

# ---------------- LOGGING SETUP ---------------- #
logging.basicConfig(
    filename="network_logs.txt",
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)

def packet_callback(packet):

    if IP in packet:

        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto

        protocol_name = "Unknown"

        if proto == 6:
            protocol_name = "TCP"
        elif proto == 17:
            protocol_name = "UDP"
        elif proto == 1:
            protocol_name = "ICMP"

        packet_info = (
            f"\n[+] Packet Detected\n"
            f"Source IP      : {ip_src}\n"
            f"Destination IP : {ip_dst}\n"
            f"Protocol       : {protocol_name}\n"
        )

        # TCP Port Details
        if packet.haslayer(TCP):
            packet_info += (
                f"Source Port    : {packet[TCP].sport}\n"
                f"Destination Port: {packet[TCP].dport}\n"
            )

        # UDP Port Details
        elif packet.haslayer(UDP):
            packet_info += (
                f"Source Port    : {packet[UDP].sport}\n"
                f"Destination Port: {packet[UDP].dport}\n"
            )

        # Payload Extraction
        if packet.haslayer(Raw):
            try:
                payload = packet[Raw].load.decode(errors="ignore")
                packet_info += f"Payload Preview: {payload[:60]}\n"
            except:
                packet_info += "Payload Preview: Unable to decode\n"

        print(packet_info)

        # Save logs
        logging.info(packet_info)

def main():

    print("=" * 60)
    print("      ADVANCED NETWORK PACKET SNIFFER")
    print("=" * 60)
    print("[*] Capturing TCP, UDP & ICMP packets...")
    print("[*] Press CTRL + C to stop.\n")

    try:
        sniff(
            filter="tcp or udp or icmp",
            prn=packet_callback,
            store=0
        )

    except RuntimeError as e:

        print(f"[!] Runtime Error: {e}")
        print("[*] Trying Windows fallback mode...")

        try:
            from scapy.arch.windows import WindowsL3Socket
            conf.L3socket = WindowsL3Socket

            sniff(
                filter="tcp or udp or icmp",
                prn=packet_callback,
                store=0
            )

        except Exception as fallback_error:
            print(f"[!] Fallback Failed: {fallback_error}")
            print("[!] Install NPCAP with WinPcap compatibility mode.")

    except KeyboardInterrupt:
        print("\n[-] Sniffer stopped safely.")
        sys.exit(0)

if __name__ == "__main__":
    main()