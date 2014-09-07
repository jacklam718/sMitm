#!/usr/bin/env python
# -*- coding: utf-8 -*-
from scapy.all import *
def log(message):
    log_time = time.strftime("%H-%M-%S [*]")
    print("\033[31m%s\033[0m: \033[32m%s\033[0m" % (log_time, message))

class Parser:
    web_ports   = [80, 443]
    mail_ports  = [25, 26, 110, 143, 993, 995]
    ftp_ports   = [20, 21]
    telnet_ports= [23]
    vnc_ports   = [5500, 5800, 5900]
    whats_ports = [5223, 5228, 4244, 5242, 5222]

    def parseWhatsApp(self, load):
        pass

    def parseWeb(self, load):
        load = load.split('\r\n\r\n')
        header_lines, content_lines = (load[0].split("\n"), load[1:])
        # first line of first word there is HTTP type
        http_type  = header_lines[0][0:header_lines[0].find("/")].strip()
        has_image  = False
        header = { }
        body   = ""
        if not http_type in ["GET", "HTTP", "HOST"]:
            return
        for line in header_lines:
            try:
                key, value = line.split(":", 1)
                header[key.lower()] = value
            except ValueError:
                pass
        if not has_image and content_lines:     # if has body, to decode them
            try:
                charset = header.get("content-type").split(";")[1]
                charset = charset[charset.find("=")+1:]  # to get the body charset type
            except (AttributeError, IndexError):
                charset = "utf-8"
            for line in content_lines:
                try:
                    body += line.decode(charset) + "\n" # to decode body follow the charset type
                except:
                    continue
        return (http_type, header, body)

    def parseFtp(self, load, src_ip, dst_ip):
        load = load.replace("\r\n", "")
        if "USER" in load:
            print(R+"[*] FTP " + G + load + " SERVER: " + dst_ip + W)
        elif "PASS" in load:
            
        elif "authentication failed" in load:
            pass

    def parseMail(self, load):
        pass

    def parseTelnet(self, load):
        load = load.split(" ", 1)
        if len(load) == 2:
            cmd, arg = load
        elif len(load) == 1:
            cmd, arg = (load, "")
        return (cmd, arg)

    def parseVnc(self, load):
        pass