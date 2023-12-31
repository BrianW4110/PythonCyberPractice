#reads one packet from host network
import socket
import os

host = host = socket.gethostbyname(socket.gethostname())

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

# ctypes class for reading packet headers in C (ctype method)
# from ctypes import *
# import struct

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

        # gives protocal constants to their names
        self.protocal_map = {1: "ICMP", 6: "TCP", 17: "UDP"}

#for reading ICMP messages
class ICMP:
    def __init__(self,buff):
        header = struct.unpack('<BBHHH', buff)
        self.type = header[0]
        self.code = header[1]
        self.sum = header[2]
        self.id = header[3]
        self.seq = header[4]

