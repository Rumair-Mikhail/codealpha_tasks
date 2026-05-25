from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP

packet_count = 0

def process_packet(packet):
    global packet_count
    packet_count += 1

    print(f"\n--- Packet #{packet_count} ---")

    if packet.haslayer(IP):
        ip_layer = packet[IP]
        print(f"Source IP      : {ip_layer.src}")
        print(f"Destination IP : {ip_layer.dst}")
        print(f"TTL            : {ip_layer.ttl}")

        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            print(f"Protocol       : TCP")
            print(f"Source Port    : {tcp_layer.sport}")
            print(f"Dest Port      : {tcp_layer.dport}")
            payload = bytes(tcp_layer.payload)
            if payload:
                print(f"Payload        : {payload[:100]}")

        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            print(f"Protocol       : UDP")
            print(f"Source Port    : {udp_layer.sport}")
            print(f"Dest Port      : {udp_layer.dport}")
            payload = bytes(udp_layer.payload)
            if payload:
                print(f"Payload        : {payload[:100]}")

        elif packet.haslayer(ICMP):
            icmp_layer = packet[ICMP]
            print(f"Protocol       : ICMP")
            print(f"Type           : {icmp_layer.type}")
            print(f"Code           : {icmp_layer.code}")

        else:
            print(f"Protocol       : Other (proto number: {ip_layer.proto})")

    else:
        print("Non-IP packet, skipping...")

print("Starting network sniffer... Press Ctrl+C to stop.\n")

try:
    sniff(prn=process_packet, store=False)
except KeyboardInterrupt:
    print(f"\nSniffer stopped. Total packets captured: {packet_count}")
