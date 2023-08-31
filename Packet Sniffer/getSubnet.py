#creates a subnet from host ip address
import socket
class getSubnetC:
    def __init__(self, host):
        hostname = host
        self.ip = socket.gethostbyname(hostname)
        last_index = self.ip.rfind('.')
        shorten = self.ip[:last_index + 1]
        self.subnet = shorten + '0/24'
        

    def method(self):
        return self.subnet
    def getIP(self):
        return self.ip