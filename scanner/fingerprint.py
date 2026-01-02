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

def service_from_banner(banner: str | None) -> str | None:
    banner = banner.strip()

    # SSH
    if banner.startswith("SSH-"):
        return "ssh"

    # FTP
    if banner.startswith("220") and "FTP" in banner.upper():
        return "ftp"

    # SMTP
    if banner.startswith("220") and "SMTP" in banner.upper():
        return "smtp"

    # POP3
    if banner.startswith("+OK") and "POP3" in banner.upper():
        return "pop3"

    # IMAP
    if banner.startswith("* OK") and "IMAP" in banner.upper():
        return "imap"

    # Redis
    if banner.startswith("-ERR") and "redis" in banner.lower():
        return "redis"
    
    # MySQL; commonly starts with or contains \x0a and mariadb
    if banner.startswith("\x0a") or "mysql" in banner.lower() or "mariadb" in banner.lower():
        return "mysql"

    return None

def service_from_port(port: int) -> str | None:
    common_portmap = {
        21: "ftp",
        22: "ssh",
        23: "telnet",
        25: "smtp",
        53: "dns",
        67: "dhcp",
        68: "dhcp",
        69: "tftp",
        80: "http",
        110: "pop3",
        111: "rpcbind",
        123: "ntp",
        135: "msrpc",
        139: "netbios-ssn",
        143: "imap",
        161: "snmp",
        162: "snmptrap",
        389: "ldap",
        443: "https",
        445: "microsoft-ds",
        465: "smtps",
        514: "syslog",
        543: "klogin",
        544: "kshell",
        587: "smtp",
        631: "ipp",
        636: "ldaps",
        993: "imaps",
        995: "pop3s",
        1433: "mssql",
        1521: "oracle",
        3306: "mysql",
        3389: "rdp",
        5432: "postgresql",
        6379: "redis",
        8080: "http",
        8443: "https",
    }
    return common_portmap.get(port)     #as dict.get() returns our str OR none by default
    

def fingerprint_general(host: str, port: int) -> dict | None:
    try:
        banner = grab_banner(host, port)
        if banner != None:
            service = service_from_banner(banner)
            certainty = "banner"
        else:
            service = service_from_port(port)
            certainty = "port"

        if service == None:
            service = "unknown/no service"
            certainty = "N/A"
            
        return {
            "service": service,
            "certainty": certainty,
            "response": banner.split("\r\n") if banner else [] #Prevents banner.split() from breaking if banner is None
        }
    except Exception:
        return None
    
#This function attempts to fingerprint HTTP ports as
#they are special and do not provide a banner upon
#TCP connection like most ports.
def fingerprint_http(host: str, port: int) -> dict | None:
    try: 
        with socket.create_connection((host, port), timeout=config.SOCKET_TIMEOUT) as sock:
            service = ""
            try:
                context = ssl.create_default_context()
                sock = context.wrap_socket(sock, server_hostname=host)
                service = "https"
            except Exception:
                service = "http"
            request = f"HEAD / HTTP/1.1\r\nHost: {host}\r\n\r\n"
            sock.sendall(request.encode())
            
            response = sock.recv(2048).decode(errors="ignore")
            
            if response.startswith("HTTP/"):
                return {
                    "service": service,
                    "response": response.split("\r\n")
                }
            else:
                return None
    except Exception:
        return None
    
