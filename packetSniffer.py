#unpacks the header to binary and assigns fields into a data structure (struct method)
import ipaddress
import struct
import os
import socket
import sys
import threading
import time
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

#creates socket + turns on promiscuous mode for windows
class Scanner:
    def __init__(self, host):
        self.host = host
        # different protocols for different operating systems
        if os.name == 'nt':
            # for Windows
            socket_protocol = socket.IPPROTO_IP
        # else:
        #     socket_protocol = socket.IPPROTO_ICMP
        
        #creates a socket with attributes that are able to communicate with packets and the IP
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
        self.socket.bind((host, 10727)) #port of zero lets OS pick port
        #IP header will be shown in packets
        self.socket.setsockopt(socket_protocol, socket.IP_HDRINCL, 1)
        #enable promiscuous mode for windows
        if os.name == 'nt':
            self.socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    def sniff(self):
        hosts_up = set([f'{str(self.host)}*'])
        try:
            while True:
                #read packet
                raw_buffer = self.socket.recvfrom(65535)[0] #65535 is the maximum size for a packet
                ip_header = IP(raw_buffer[0:20])
                if ip_header.protocol == 'ICMP':
                    # #prints packet's protocol and host + host end address
                    # print('Protocol: %s %s ->  %s' % (ip_header.protocol, ip_header.src_address, ip_header.dst_address))
                    # print(f'Version: {ip_header.ver}')
                    # print(f'Header Length: {ip_header.ihl} TTL: {ip_header.ttl}')

                    #figure where the ICMP packet starts
                    offset = ip_header.ihl * 4
                    buf = raw_buffer[offset:offset + 8]
                    #create ICMP structure
                    icmp_header = ICMP(buf)

                    # print('ICMP -> Type: %s Code: %s\n' % (icmp_header.type, icmp_header.code))

                    # check for CODE and TYPE 3
                    if icmp_header.code == 3 and icmp_header.type == 3:
                        if ipaddress.ip_address(ip_header.str_address) in ipaddress.IPv4Network(SUBNET):
                            #check for if message we sent is in given packet
                            if raw_buffer[len(raw_buffer) - len(message):] == bytes(message, 'utf8'):
                                tgt = str(ip_header.src_address)
                                if tgt != self.host and tgt not in hosts_up:
                                    hosts_up.add(str(ip_header.src_address))
                                    print(f'Host Up: {tgt}')

        #used to respond to CTRL-C (user stops script)
        except KeyboardInterrupt:
            #for windows turn of promiscuous mode
            if os.name == 'nt':
                self.socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            print('\nUser stopped.')
            if hosts_up:
                print(f'\n\nSummary: Hosts up on {SUBNET}')
            for host in sorted(hosts_up):
                print(f'{host}')
            print('')
            sys.exit()
        
if __name__ == '__main__':
    if len(sys.argv) == 2:
        host = sys.argv[1]
    else:
        host = socket.gethostbyname(socket.gethostname())
    s = Scanner(host)
    time.sleep(5)
    t = threading.Thread(target=udp_sender)
    t.start()
    s.sniff()
