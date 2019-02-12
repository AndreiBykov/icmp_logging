from bcc import BPF

import sys
import socket
import os
import datetime

from sys import argv

if len(argv) == 2:
    interface = argv[1]
    write_to_file = False
elif len(argv) == 3:
    interface = argv[1]
    file = open(argv[2], "a+")
    write_to_file = True
else:
    print("USAGE: sudo python %s <if_name> [<filename>]" % argv[0])
    exit()
 
print ("binding socket to '%s'" % interface)    

bpf = BPF(src_file = "icmp6_filter.c", debug = 0)

function_tcp_filter = bpf.load_func("icmp6_filter", BPF.SOCKET_FILTER)

BPF.attach_raw_socket(function_tcp_filter, interface)

socket_fd = function_tcp_filter.sock

sock = socket.fromfd(socket_fd, socket.PF_PACKET, socket.SOCK_RAW, socket.IPPROTO_IP)

sock.setblocking(True)

ETH_HLEN = 14 #Ethernet header length in bytes
IPV6_HLEN = 40 #IPv6 header length in bytes

while 1:
    packet_str = os.read(socket_fd, 2048)
    
    packet = bytearray(packet_str)

    icmp_code = packet[ETH_HLEN + IPV6_HLEN + 6] << 8 | packet[ETH_HLEN + IPV6_HLEN + 7]
    echo_id = packet[ETH_HLEN + IPV6_HLEN + 4] << 8 | packet[ETH_HLEN + IPV6_HLEN + 5]

    out_str = str(echo_id) + ' ' + str(datetime.datetime.now()) + ' ' + str(icmp_code)
    print(out_str)

    if(write_to_file):
        file.write(out_str + '\n')
        file.flush()
