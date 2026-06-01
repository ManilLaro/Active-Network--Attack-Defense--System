from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP, Raw, send
import sys

delta = {
    "c2s": 0,    # adjustments for client -> server stream
    "s2c": 0     # adjustments for server -> client stream
}

# Dedup on full 5-tuple + SEQ to avoid false collisions
seen = set()

def direction_of(pkt):
    """Return 'c2s' or 's2c' based on destination port."""
    return "c2s" if pkt[TCP].dport == 4444 else "s2c"

def opposite(d):
    return "s2c" if d == "c2s" else "c2s"

def send_fake_ack(spkt, d):
    """
    Immediately ACK the sender using *their* view of the world
    (un-adjusted values) so they don't retransmit while we decide.
    """
    ip = spkt[IP]
    tcp = spkt[TCP]
    payload_len = len(spkt[Raw].load) if Raw in spkt else 0
    
    fake = (
        IP(src=ip.dst, dst=ip.src) /
        TCP(
            sport=tcp.dport,
            dport=tcp.sport,
            flags="A",
            seq=tcp.ack,                # sender's view of peer SEQ
            ack=tcp.seq + payload_len,  # ACK everything sender just sent
            window=tcp.window
        )
    )
    send(fake, verbose=0)
def rebuild(spkt, new_payload_bytes, d):
    ip = spkt[IP]
    tcp = spkt[TCP]
    
    new_seq = tcp.seq + delta[d]
    new_ack = tcp.ack - delta[opposite(d)]
    
    pkt = (
        IP(src=ip.src, dst=ip.dst, ttl=ip.ttl) /
        TCP(
            sport=tcp.sport,
            dport=tcp.dport,
            flags=tcp.flags,
            seq=new_seq,
            ack=new_ack,
            window=tcp.window,
            options=tcp.options
        ) /
        Raw(load=new_payload_bytes)
    )
    return bytes(pkt)

def process_packet(pkt):
    spkt = IP(pkt.get_payload())
    
    # Only intercept TCP segments with payload
    if not (TCP in spkt and Raw in spkt):
        # Still need to adjust SEQ/ACK on bare ACKs if deltas are nonzero
        if TCP in spkt and (delta["c2s"] or delta["s2c"]):
            d  = direction_of(spkt)
            ip = spkt[IP]
            tcp = spkt[TCP]
            adj = (IP(src=ip.src, dst=ip.dst, ttl=ip.ttl) /
                   TCP(sport=tcp.sport, dport=tcp.dport, flags=tcp.flags, seq=tcp.seq + delta[d],
                       ack=tcp.ack - delta[opposite(d)], window=tcp.window, options=tcp.options))
            pkt.set_payload(bytes(adj))
        pkt.accept()
        return
      # Dedup
flow_key = (
    spkt[IP].src, spkt[IP].dst,
    spkt[TCP].sport, spkt[TCP].dport,
    spkt[TCP].seq
)

if flow_key in seen:
    pkt.drop()
    return

seen.add(flow_key)

d = direction_of(spkt)
label = "CLIENT -> SERVER" if d == "c2s" else "SERVER -> CLIENT"
payload = spkt[Raw].load
orig_len = len(payload)

# Fake-ACK the sender immediately (before we stall on input)
send_fake_ack(spkt, d)

print(f"\n{'='*50}")
print(f"[INTERCEPTED] {label}")
print(f"[FROM] {spkt[IP].src}:{spkt[TCP].sport}")
print(f"[TO]   {spkt[IP].dst}:{spkt[TCP].dport}")
print(f"[PAYLOAD] {payload.decode(errors='replace').strip()}")
print(f"[LENGTH]  {orig_len} bytes")
print(f"[SEQ DELTAS] c2s={delta['c2s']:+d} s2c={delta['s2c']:+d}")
print(f"{'='*50}")

print("[1] Send as-is")
print("[2] Modify payload")
print("[3] Drop packet")

while True:
    choice = input("Choice: ").strip()

    if choice == "1":
        pkt.set_payload(rebuild(spkt, payload, d))
        pkt.accept()
        print("[+] Packet forwarded as-is.")
        break

    elif choice == "2":
        new_payload = (input("Enter new payload: ") + "\n").encode()
        new_len = len(new_payload)

        # Rebuild with current deltas THEN update delta for length change
        pkt.set_payload(rebuild(spkt, new_payload, d))
        delta[d] += (new_len - orig_len)

        pkt.accept()
        print(
            f"[+] Forwarded modified ({orig_len}->{new_len} bytes). "
            f"Delta {d} now {delta[d]:+d}"
        )
        break

    elif choice == "3":
        # Receiver never sees these bytes -> delta shrinks
        delta[d] -= orig_len

        pkt.drop()
        print(
            f"[+] Dropped {orig_len} bytes. "
            f"Delta {d} now {delta[d]:+d}"
        )
        break

    else:
        print("[-] Invalid choice. Enter 1, 2, or 3.")
      nfq = NetfilterQueue()
nfq.bind(0, process_packet)
print("\n[*] Interceptor running. Waiting for packets...")
print("[*] Press Ctrl+C to stop.\n")
try:
    nfq.run()
except KeyboardInterrupt:
    print("\n[*] Stopping interceptor...")
    nfq.unbind()
    sys.exit(0)
