#By: Oliver Osmond
#Created on: 2025-12-29
#Description: This file handles the fingerprinting/banner grabbing of a host's open ports

import socket
import ssl
from scanner import config

#This function grabs a banner from most hosts, such as
#SSH, FTP, &c. Host and port must be provided, returns
#the banner as a string.
def grab_banner(host:str, port:int) -> str | None:
    try:
        with socket.create_connection((host, port), timeout=config.SOCKET_TIMEOUT) as sock:
            data = sock.recv(1024)
            return data.decode(errors="ignore").strip()
    except Exception:
        return None

#This function attempts to fingerprint HTTP ports as
#they are special and do not provide a banner upon
#TCP connection like most ports.
def fingerprint_http(host: str, port: int) -> dict | None:
    try: 
        with socket.create_connection((host, port), timeout=config.SOCKET_TIMEOUT) as sock:
            if port == 443:
                context = ssl.create_default_context()
                sock = context.wrap_socket(sock, server_hostname=host)
            
            request = f"HEAD / HTTP/1.1\r\nHost: {host}\r\n\r\n"
            sock.sendall(request.encode())
            
            response = sock.recv(2048).decode(errors="ignore")
            return {
                "service": "http",
                "response": response.split("\r\n")
            }
    except Exception:
        return None