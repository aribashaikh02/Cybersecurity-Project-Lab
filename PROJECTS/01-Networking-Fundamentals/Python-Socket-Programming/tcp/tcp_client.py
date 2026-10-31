import socket

# Create a TCP socket
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect to our local server
client.connect(("127.0.0.1", 12345))

# Send a message
client.send("Hello TCP Server".encode())

# Receive and display the response
print(client.recv(1024).decode())

# Close the connection
client.close()
