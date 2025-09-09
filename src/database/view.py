from scapy.all import sniff

iface = r"\\Device\\NPF_{A9AC6786-50AA-42B0-9B9A-8A580A2E8299}"  # Wi-Fi
print(f"Sniffing on: {iface}")

packets = sniff(iface="Wi-Fi", count=5, timeout=10)
print(f"Captured {len(packets)} packets")

for pkt in packets:
    print(pkt.summary())
