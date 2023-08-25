#creates a subnet from host ip address
import socket

hostname = socket.gethostname()
ip = socket.gethostbyname(hostname)
shorten = ip[:len(ip) - 3]
subnet = shorten + '0/24'
print(subnet)