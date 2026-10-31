import socket

c = socket.socket()

c.connect(("localhost", 9000))  # connect to server
print(c.recv(1024).decode())  # receive data from server
