#unpacks the header to binary and assigns fields into a data structure (struct method)
import ipaddress
import struct
import os
import socket
import sys
import getSubnet


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

class ICMP:
    def __init__(self, buff):
        header = struct.unpack('<BBHHH', buff)
        self.type = header[0]
        self.code = header[1]
        self.sum = header[2]
        self.id = header[3]
        self.seq = header[4]

#takes user host name to calculate subnet
host = socket.gethostname()
subnetObj = getSubnet.getSubnetC(host)

#subnet to scan from
SUBNET = subnetObj.method()

message = 'Yourself or Someone like you'
# sends UDP datagrams with of given message
def udp_sender():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
        for ip in ipaddress.ip_network(SUBNET).hosts():
            sender.sendto(bytes(message, 'utf8'), (str(ip), 10727))

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
            if ip_header.protocol == 'ICMP':
                #prints packet's protocol and host + host end address
                print('Protocol: %s %s ->  %s' % (ip_header.protocol, ip_header.src_address, ip_header.dst_address))
                print(f'Version: {ip_header.ver}')
                print(f'Header Length: {ip_header.ihl} TTL: {ip_header.ttl}')

                #figure where the ICMP packet starts
                offset = ip_header.ihl * 4
                buf = raw_buffer[offset:offset + 8]
                #create ICMP structure
                icmp_header = ICMP(buf)
                print('ICMP -> Type: %s Code: %s\n' % (icmp_header.type, icmp_header.code))
    
    except KeyboardInterrupt:
        #for windows turn of promiscuous mode
        if os.name == 'nt':
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        sys.exit()
        
if __name__ == '__main__':
    if len(sys.argv) == 2:
        host = sys.argv[1]
    else:
        host = socket.gethostbyname(socket.gethostname())
    sniff(host)
