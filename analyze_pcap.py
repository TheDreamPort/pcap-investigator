#!/usr/bin/env python3
import sys

from scapy.all import *
from scapy.layers.http import *

if __name__ == "__main__":
    scapy_cap = rdpcap( sys.argv[1] )
    for packet in scapy_cap:
        print(packet)
        try:
            if packet[TCP]:
                payload = bytes(packet[TCP].payload)
                url_path = payload[payload.index(b"GET ")+4:payload.index(b" HTTP/1.0")].decode("utf8")
                http_header_raw = payload[:payload.index(b"\r\n\r\n")+2]
                http_header_parsed = dict(re.findall(r"(?P<name>.*?): (?P<value>.*?)\r\n", http_header_raw.decode("utf8")))
                url = http_header_parsed["Host"] + url_path + "\n"
                # fd.write(url.encode())
                print(payload)
        except:
            pass
