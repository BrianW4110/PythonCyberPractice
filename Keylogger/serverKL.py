import socket
host = socket.gethostname()
port = 10727
s = socket.socket()
s.bind((host, port))
s.listen(5)

print('Waiting for client...')
conn,addr = s.accept()
print('Connected by ' + addr[0])

while True:
    data = conn.recv(1024)
    if data:
        key = data.decode('utf-8')
        with open("log.txt", 'a') as f:
            f.write(key)
