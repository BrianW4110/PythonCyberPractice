# ctypes class for reading packet headers in C (ctype method)
# from ctypes import *

# class IP(Structure):
#     _fields_ = [
#         ("version", c_ubyte, 4),
#         ("ihl", c_ubyte, 4), #internet hdr length (signifies start of header)
#         ("tos", c_ubyte, 8), #type of service (priority of packet)
#         ("len", c_ushort, 16), #length
#         ("id", c_ushort, 16),
#         ("offset", c_ushort, 16), #fragment offset (identify order sequence of fragmented packets)
#         ("ttl" , c_ubyte, 8), #time to live (time limit before being discarded by network)
#         ("protocol_num", c_ubyte, 8),
#         ("sum", c_ushort, 16), #hdr checksum (identifies errors in the packet)
#         ("src", c_int32, 32), #source IP
#         ("dst", c_int32, 32), #destination IP
#     ]

#     #constructor 
#     def __new__(cls, socket_buffer=None):
#         return cls.from_buffer_copy(socket_buffer)
#     def __init__(self, socket_buffer=None):
#         # converts to human readable IP 
#         self.src_address = socket.inet_ntoa(struct.pack("<L", self.src))
#         self.dst_address = socket.inet_ntoa(struct.pack("<L", self.dst))

#unpacks the header to binary and assigns fields into a data structure (struct method)
import ipaddress
import struct
import os
import socket
import sys

class IP:
    def __init__(self, buff=None):
        #unpacks the fields of the header in binary from bytes
        header = struct.unpack('<BBHHHBBH4s4s', buff)
        #removes first 4 bits (bitshifting)
        self.ver = header[0] >> 4
        #takes the next 4 bits
        self.ihl = header[0] & 0xF

        self.tos = header[1]
        self.len = header[2]
        self.id = header[3]
        self.offset = header[4]
        self.ttl = header[5]
        self.protocol_num = header[6]
        self.sum = header[7]
        self.src = header[8]
        self.dst = header[9]

        # converts to human readable IP 
        self.src_address = ipaddress.ip_address(self.src)
        self.dst_address = ipaddress.ip_address(self.dst)

        # gives protocol constants to their names
        self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except Exception as e:
            print('%s No protocol for %s' % (e, self.protocol_num))
        self.protocol = str(self.protocol_num)

def sniff(host):
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
    try:
        while True:
            # reading packets
            raw_buffer = sniffer.recvfrom(65535)[0] #65535 is the maximum size for a packet
            ip_header = IP(raw_buffer[0:20])
            #prints packet's protocol and host + host end address
            print('Protocol: %s %s ->  %s' % (ip_header.protocol, ip_header.src_address, ip_header.dst_address))
    
    except KeyboardInterrupt:
        #for windows turn of primiscuous mode
        if os.name == 'nt':
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        sys.exit()
        
if __name__ == '__main__':
    if len(sys.argv) == 2:
        host = sys.argv[1]
    else:
        host = socket.gethostname()
    sniff(host)
