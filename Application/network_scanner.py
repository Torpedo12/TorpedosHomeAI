from scapy.all import ARP, Ether, srp

def scan_network(network_range):
    devices = []

    arp_request = ARP(pdst=network_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")

    packet = broadcast / arp_request

    answered_packets = srp(packet, timeout=2, verbose=False)[0]

    for sent, received in answered_packets:
        devices.append({
            "ip": received.psrc,
            "mac": received.hwsrc
        })

    return devices


if __name__ == "__main__":
    network = "10.0.0.1/24"

    result = scan_network(network)

    print("Connected Devices:")
    print("------------------")

    for device in result:
        print("IP:", device["ip"], "MAC:", device["mac"])