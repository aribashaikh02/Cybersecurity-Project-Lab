import socket

# Create a UDP socket
client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Server address and port
server_addr = ("127.0.0.1", 12346)

# Send a message to the UDP server
client.sendto("Hello UDP Server".encode(), server_addr)

# Receive the response from the server
data, _ = client.recvfrom(1024)
print(data.decode())
