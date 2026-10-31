import socket

# Create a socket object
s = socket.socket()
print("socket created")

# Bind the socket to localhost and port 9000
s.bind(("localhost", 9000))

# Listen for incoming client connections (maximum 3 queued connections)
s.listen(3)
print("waiting for connection")

# Continuously accept client connections
while True:
    # Accept a client connection and get its address
    c, addr = s.accept()
    print("connected to", addr)

    # Send a welcome message to the client
    c.send(bytes("welcome", "utf-8"))

    # Close the client connection
    c.close()
