import socket

# Create a UDP socket
server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Bind the server to localhost and port 12346
server.bind(("127.0.0.1", 12346))

# Receive data from a client
data, addr = server.recvfrom(1024)

# Send the received message back with an Echo prefix
server.sendto(f"Echo {data.decode()}".encode(), addr)
