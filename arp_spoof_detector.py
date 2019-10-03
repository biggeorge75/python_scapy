import scapy.all as scapy

def mac_cim_beolvasas(ip):
    arp_keres = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    egyesitett_keres = broadcast/arp_keres
    valaszolt = scapy.srp(egyesitett_keres, timeout=1, verbose=False)[0]

    return valaszolt[0][1].hwsrc

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=csomag_feldolgozas)

def csomag_feldolgozas(csomag):
    if csomag.haslayer[scapy.ARP]:
        if csomag[scapy.ARP].op == 2:
            try:
                igazi_mac = mac_cim_beolvasas(csomag[scapy.ARP].psrc)
                valasz_mac = csomag[scapy.ARP].hwsrc

                if igazi_mac != valasz_mac:
                    print('ARP spoofing támadás alatt áll a gép!!!')
            except IndexError:
                pass