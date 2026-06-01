from scapy.all import Ether, ARP, sniff, srp, conf
import subprocess

IFACE = "eth0"
conf.iface = IFACE

# Build a trusted ARP table at startup by sending real ARP requests
trusted = {}

def discover_real_mac(ip):
    """Get the real MAC of an IP via a legitimate ARP request."""
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=2, iface=IFACE, verbose=False)
    if ans:
        return ans[0][1].hwsrc
    return None

def fix_arp_entry(ip, real_mac):
    """Overwrite the poisoned ARP cache entry with the correct one."""
    subprocess.run(["arp", "-d", ip], stderr=subprocess.DEVNULL)
    subprocess.run(["arp", "-s", ip, real_mac])
    print(f"[+] FIXED: Restored {ip} -> {real_mac}")

def process_packet(pkt):
    if not pkt.haslayer(ARP):
        return
        
    arp = pkt[ARP]
    
    # We only care about ARP replies (is-at, op=2)
    if arp.op != 2:
        return
        
    src_ip = arp.psrc
    src_mac = arp.hwsrc
    
    # If we've never seen this IP, trust the first reply and store it
    if src_ip not in trusted:
        trusted[src_ip] = src_mac
        print(f"[*] Learned: {src_ip} -> {src_mac}")
        return
        
    # If the MAC changed for a known IP - likely poisoning
    if trusted[src_ip] != src_mac:
        print(f"[!] ALERT: {src_ip} changed from {trusted[src_ip]} to {src_mac} - possible ARP spoof!")
        fix_arp_entry(src_ip, trusted[src_ip])

def main():
    print("[*] Building trusted ARP table from live discovery...")
    
    # Pre-discover MACs for the local subnet (adjust range as needed)
    for i in range(1, 5):
        ip = f"10.0.0.{i}"
        mac = discover_real_mac(ip)
        if mac:
            trusted[ip] = mac
            print(f"[*] Trusted: {ip} -> {mac}")
            
    print(f"\n[*] Monitoring ARP traffic on {IFACE}... Ctrl+C to stop\n")
    sniff(iface=IFACE, filter="arp", prn=process_packet, store=0)

if __name__ == "__main__":
    main()
