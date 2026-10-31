# Python Socket Programming

A hands-on introduction to network communication using Python's built-in `socket` module. This project explores the fundamentals of client-server communication, TCP and UDP protocols, IP address resolution, and basic network connectivity testing.

Part of **Cybersecurity ProjectLab** — a collection of practical projects documenting my journey into cybersecurity, networking, and related technologies.

---

## Overview

This project contains practical Python implementations demonstrating how computers communicate over a network using sockets.

The exercises cover:

- Basic client-server communication
- TCP connection-oriented communication
- UDP connectionless communication
- IP address resolution using DNS
- Testing external TCP connectivity

## Project Structure

```text
Python-Socket-Programming/
│
├── server.py
├── client.py
├── ip_socket.py
│
├── tcp/
│   ├── tcp_server.py
│   ├── tcp_client.py
│   └── google_client.py
│
├── udp/
│   ├── udp_server.py
│   └── udp_client.py
│
└── README.md
```

## Concepts Covered

### 1. Basic Client-Server Communication

Files: `server.py`, `client.py`

- Creating a socket.
- Binding a server to localhost.
- Listening for incoming connections.
- Accepting client connections.
- Sending and receiving messages.

Default port: `9000`

### 2. TCP Communication

Files: `tcp/tcp_server.py`, `tcp/tcp_client.py`

TCP (Transmission Control Protocol) establishes a connection between two endpoints before exchanging data.

This implementation demonstrates:

- TCP socket creation using `SOCK_STREAM`.
- Establishing a connection between client and server.
- Sending messages using `send()`.
- Receiving responses using `recv()`.
- Implementing a simple echo server.

Default port: `12345`

### 3. UDP Communication

Files: `udp/udp_server.py`, `udp/udp_client.py`

UDP (User Datagram Protocol) allows data to be transmitted without establishing a connection beforehand.

This implementation demonstrates:

- Creating UDP sockets using `SOCK_DGRAM`.
- Sending data using `sendto()`.
- Receiving data using `recvfrom()`.
- Building a simple UDP echo server.

Default port: `12346`

### 4. IP Address Resolution

File: `ip_socket.py`

Uses Python's `socket.gethostbyname()` to resolve a domain name into its corresponding IPv4 address through DNS.

### 5. External TCP Connectivity Test

File: `tcp/google_client.py`

Attempts to establish a TCP connection with an external server on port `443` (HTTPS).

Demonstrates:

- Connecting to a remote IP address.
- Setting connection timeouts.
- Handling connection errors.
- Closing sockets safely.

**Note:** This tests TCP connectivity only; it does not perform an HTTPS or TLS handshake.

---

## Requirements

- Python 3.x
- Basic understanding of Python.
- Basic understanding of computer networking.

No external Python packages are required. The project uses Python's built-in `socket` module.

## Getting Started

### 1. Clone the Repository

```bash
git clone YOUR_REPOSITORY_URL
```

Navigate to the project folder:

```bash
cd Cybersecurity-ProjectLab/PROJECTS/Python-Socket-Programming
```

### 2. Run Basic Client-Server Communication

Open two separate terminals.

**Terminal 1 — Start the server:**

```bash
python server.py
```

**Terminal 2 — Start the client:**

```bash
python client.py
```

### 3. Run TCP Communication

**Terminal 1:**

```bash
python tcp/tcp_server.py
```

**Terminal 2:**

```bash
python tcp/tcp_client.py
```

Expected client output:

```text
Echo Hello TCP Server
```

### 4. Run UDP Communication

**Terminal 1:**

```bash
python udp/udp_server.py
```

**Terminal 2:**

```bash
python udp/udp_client.py
```

Expected client output:

```text
Echo Hello UDP Server
```

### 5. Run IP Address Resolution

```bash
python ip_socket.py
```

### 6. Test External TCP Connectivity

```bash
python tcp/google_client.py
```

A successful connection prints:

```text
Connected successfully!
```

The result depends on network availability and whether the remote endpoint accepts the connection.

---

## TCP vs UDP

| Feature | TCP | UDP |
|---|---|---|
| Connection | Connection-oriented | Connectionless |
| Reliability | Reliable delivery | No delivery guarantee |
| Ordering | Preserves byte-stream order | No ordering guarantee |
| Speed | More overhead | Lower overhead |
| Example use | Web browsing, file transfer | DNS, streaming, online gaming |

## Learning Objectives

Through this project, I explored:

- How client-server architecture works.
- How applications communicate using network sockets.
- The differences between TCP and UDP.
- How IP addresses and ports identify network endpoints.
- How DNS resolves domain names.
- How to establish and test network connections using Python.

## Future Improvements

Potential additions to this project:

- TCP multi-client server using threading.
- Basic port scanner for authorized testing.
- Network packet analysis.
- Client-server chat application.
- Network connection monitoring.
- Improved error handling and socket management.

## Disclaimer

This repository is intended for educational purposes and authorized networking experiments.

Only test network connections and systems that you own or have explicit permission to assess.

## Author

**Ariba Shaikh**

Cybersecurity | Python | Networking | AI

[GitHub](https://github.com/aribashaikh02)