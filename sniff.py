import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from scapy.utils import *
from collections import OrderedDict
from threading import Thread, Event
import time
from packet import DefaultPacket
import io
from contextlib import redirect_stdout

conf.promisc = True

class PacketSniffer(object):
    def __init__(self, interface='wlan0', protocol = ""):
        self.interface = interface
        self.protocol = protocol
        self.cookie = False
        self.num = 0

    def refactor(self, packet):
        try:
            data = DefaultPacket()
            with io.StringIO() as buf, redirect_stdout(buf):
                packet.show()
                data.whole = buf.getvalue()
            data.source_mac = packet.src
            data.destination_mac = packet.dst
            data.time = packet.time
            data.summary = packet.summary()
            data.packetdata = packet.show
            data.no = self.num
            while packet:
                if type(packet) is NoPayload:
                    break
                elif type(packet) is IP:
                    data.source_ip = packet.src
                    data.destination_ip = packet.dst
                    if TCP or UDP in packet:
                        if TCP in packet:
                            data.packetype = "TCP"
                            data.source_port = packet[TCP].sport
                            data.destination_port = packet[TCP].dport
                            try:
                                print('[*] Check Output')
                                data.packetraw = packet[Raw].load.decode('utf-8')
                                print(packet[Raw])
                            except:
                                pass
                        elif UDP in packet:
                            data.source_port = packet[UDP].sport
                            data.destination_port = packet[UDP].dport
                            if DNS in packet:
                                data.packetype = "DNS"
                                data.packetquery = packet[DNSQR].qname.decode('utf-8')
                        elif ARP in packet:
                            pass

                packet = packet.payload
            self.num += 1
            return data
        except:
            pass

    def run(self):
        if self.cookie:
            return self.refactor(sniff(filter=self.protocol, iface='eth0', store=1, count=1)[-1])


if __name__ == "__main__":
    ps = PacketSniffer()
