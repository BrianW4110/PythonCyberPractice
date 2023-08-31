import getSubnet
import socket

if __name__ == '__main__':
    host = socket.gethostname()
    subObj = getSubnet.getSubnetC(host)
    print(subObj.method())
    print("\n", subObj.getIP())