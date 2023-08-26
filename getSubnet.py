#creates a subnet from host ip address
import socket
class getSubnetC:
    def __init__(self, host):
        hostname = host
        ip = socket.gethostbyname(hostname)
        shorten = ip[:len(ip) - 3]
        self.subnet = shorten + '0/24'
        

    def method(self):
        return self.subnet