import socket
import os

host = socket.gethostname()

def main():
    # different protocols for different operating systems
    if os.name == 'nt':
        # for Windows
        socket_protocol = socket.IPPROTO_IP
    # else:
    #     socket_protocol = socket.IPPROTO_ICMP
    
    #creates a socket with attributes that are able to communicate with packets and the IP
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
    sniffer.bind((host, 10727))
    #IP header will be shown in packets
    sniffer.setsockopt(socket_protocol, socket.IP_HDRINCL, 1)
    #enable promiscuous mode for windows
    if os.name == 'nt':
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    print(sniffer.recvfrom(65565))
    if os.name =='nt':
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

if __name__ == '__main__':
    main()

# ctypes class for reading packet headers
from ctypes import *
import struct

class IP(Structure):
    _fields_ = [
        ("ihl", c_ubyte, 4), #internet hdr length (signifies start of header)
        ("version", c_ubyte, 4),
        ("tos", c_ubyte, 8), #type of service (priority of packet)
        ("len", c_ushort, 16), #length
        ("id", c_ushort, 16),
        ("offset", c_ushort, 16), #fragment offset (identify order sequence of fragmented packets)
        ("ttl" , c_ubyte, 8), #time to live (time limit before being discarded by network)
        ("protocol_num", c_ubyte, 8),
        ("sum", c_ushort, 16), #hdr checksum (identifies errors in the packet)
        ("src", c_int32, 32), #source IP
        ("dst", c_int32, 32), #destination IP
    ]
