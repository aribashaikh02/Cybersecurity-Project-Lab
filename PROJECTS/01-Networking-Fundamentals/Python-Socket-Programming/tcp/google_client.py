import socket

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.settimeout(5)

try:
    client.connect(("142.251.152.119", 443))
    print("Connected successfully!")
except OSError as e:
    print("Error:", e)
finally:
    client.close()
