#!/usr/bin/env python3

# Python DNS query client
#
# Example usage:
#   ./dns.py --type=A --name=www.pacific.edu --server=8.8.8.8
#   ./dns.py --type=AAAA --name=www.google.com --server=8.8.8.8

# Should provide equivalent results to:
#   dig www.pacific.edu A @8.8.8.8 +noedns
#   dig www.google.com AAAA @8.8.8.8 +noedns
#   (note that the +noedns option is used to disable the pseduo-OPT
#    header that dig adds. Our Python DNS client does not need
#    to produce that optional, more modern header)


from dns_tools import dns  # Custom module for boilerplate code
from dns_tools import dns_header_bitfields

import argparse
import ctypes
import random
import socket
import struct
import sys

def main():

    # Setup configuration
    parser = argparse.ArgumentParser(description='DNS client for ECPE 170')
    parser.add_argument('--type', action='store', dest='qtype',
                        required=True, help='Query Type (A or AAAA)')
    parser.add_argument('--name', action='store', dest='qname',
                        required=True, help='Query Name')
    parser.add_argument('--server', action='store', dest='server_ip',
                        required=True, help='DNS Server IP')

    args = parser.parse_args()
    qtype = args.qtype
    qname = args.qname
    server_ip = args.server_ip
    port = 53
    server_address = (server_ip, port)

    if qtype not in ("A", "AAAA"):
        print("Error: Query Type must be 'A' (IPv4) or 'AAAA' (IPv6)")
        sys.exit()

    # Create UDP socket
    # ---------
    # STUDENT TO-DO
    # ---------
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Generate DNS request message
    # ---------
    # STUDENT TO-DO
    # ---------
    print("Sending request for " + qname + ", type " + qtype + ", to server " + server_ip + ", port %d" % port)

    messageID = random.randrange(0, 65535, 1)
    flags = dns_header_bitfields()
    flags.QR = 0
    flags.OPCODE = 0
    flags.AA = 0
    flags.TC = 0
    flags.RD = 1
    flags.RA = 0
    flags.RESERVE = 2
    flags.RCODE = 0

    site = qname.split(".")
    web_bytes = bytearray()

    for domain in site:
        web_bytes = web_bytes + struct.pack("!B", len(domain)) + domain.encode()

    web_bytes = web_bytes + struct.pack("!B", 0)

    QDCount = 1
    ANCount = 0
    NSCount = 0
    ARCount = 0

    raw_bytes = struct.pack("!H", messageID) + bytes(flags) + struct.pack("!H", QDCount) + struct.pack("!H", ANCount) + struct.pack("!H", NSCount) + struct.pack("!H", ARCount) + web_bytes

    if qtype == "A":
        raw_bytes = raw_bytes + struct.pack("!H", 1)
    else:
        raw_bytes = raw_bytes + struct.pack("!H", 28)

    raw_bytes = raw_bytes + struct.pack("!H", 1)

    # Send request message to server
    # (Tip: Use sendto() function for UDP)
    # ---------
    # STUDENT TO-DO
    # ---------

    sock.sendto(raw_bytes, server_address)

    # Receive message from server
    # (Tip: use recvfrom() function for UDP)
    # ---------
    # STUDENT TO-DO
    # ---------

    (raw_bytes, src_addr) = sock.recvfrom(4096)

    # Close socket
    # ---------
    # STUDENT TO-DO
    # ---------
    sock.close()

    # Decode DNS message and display to screen
    dns.decode_dns(raw_bytes)


if __name__ == "__main__":
    sys.exit(main())
