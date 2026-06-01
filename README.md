# Active Network Defense System: Attack Simulation & Real-Time Mitigation

This repository contains the code and documentation for an active network security project focused on simulating local network attacks and deploying real-time mitigation strategies. The project demonstrates the mechanics of Address Resolution Protocol (ARP) spoofing, Man-in-the-Middle (MITM) TCP session hijacking, and automated defensive countermeasures.

## 🎯 Project Overview
This project is broken down into three primary components:
1. **ARP Spoofing Attack:** A script that poisons the ARP cache of a target client and gateway, forcing traffic to route through the attacker's machine.
2. **Real-Time ARP Mitigation:** A defensive script that maps the local network, monitors ARP traffic for suspicious MAC address changes, and automatically restores poisoned ARP tables.
3. **MITM TCP Interceptor:** An advanced interceptor that utilizes NetfilterQueue to capture, modify, or drop TCP packets in transit while dynamically recalculating Sequence (SEQ) and Acknowledgment (ACK) numbers to prevent connection desynchronization.

## 🛠️ Technologies Used
* **OS:** Linux (Kali Linux recommended)
* **Language:** Python 3
* **Libraries:** `scapy`, `NetfilterQueue`
* **Networking Tools:** `iptables` (for routing traffic to the NFQUEUE)

## 📂 File Structure

### 1. `arpspoof.py`
Uses `scapy` to send forged ARP replies to both the client and the server. By constantly telling the server "I am the client" and the client "I am the server," the attacker successfully places themselves in the middle of the connection.

### 2. `arp_guard.py`
A real-time monitoring and mitigation tool. 
* **Phase 1 (Discovery):** Actively pings a range of IPs to build a trusted IP-to-MAC mapping table.
* **Phase 2 (Monitoring):** Sniffs network traffic for ARP replies. If an IP broadcasts a MAC address that differs from the trusted table, the script flags it as a spoofing attempt.
* **Phase 3 (Mitigation):** Automatically executes system commands (`arp -d` and `arp -s`) to delete the poisoned entry and restore the static, legitimate MAC address.

### 3. `mitm_interceptor.py`
Once the ARP spoof is active, this script binds to a Netfilter queue to intercept TCP traffic. It allows the attacker to interactively:
* **Forward** packets as-is.
* **Modify** packet payloads (e.g., altering a bank IBAN or a chat message in transit).
* **Drop** packets entirely.
* **Crucially**, it tracks byte deltas for both directions (client-to-server and server-to-client). It rewrites the `seq` and `ack` fields on the fly so that neither the client nor the server realizes the TCP session has been manipulated, preventing the connection from dying due to desynchronization.

## 🚀 Usage Instructions

> **⚠️ Disclaimer:** This project is strictly for educational purposes and authorized penetration testing. Do not use these scripts on networks where you do not have explicit permission.

### Prerequisites
Ensure you have the necessary Python libraries installed:
```bash
sudo apt-get install build-essential python3-dev libnetfilter-queue-dev
pip3 install scapy NetfilterQueue
