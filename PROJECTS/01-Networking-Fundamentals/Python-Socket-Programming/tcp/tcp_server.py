import socket

# Create a TCP socket using IPv4
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Bind the server to localhost and port 12345
server.bind(("127.0.0.1", 12345))  # Replace with the desired port number

# Listen for incoming client connections
server.listen(1)

# Accept a connection from a client
conn, addr = server.accept()

# Receive data from the client and decode it
data = conn.recv(1024).decode()

# Send the received message back with an Echo prefix
conn.send(f"Echo {data}".encode())

# Close the client connection
conn.close()

# Close the server socket
server.close()
