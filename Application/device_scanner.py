import socket

hostname = socket.gethostname()

local_ip = socket.gethostbyname(hostname)

print("Your Device Name:", hostname)

print("Your IP Address:", local_ip)