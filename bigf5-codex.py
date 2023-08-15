#!/usr/bin/env python
#
# bigf5-coder.py version 1.0
#
# https://github.com/BeeSec/bigf5-codex
#
# An encoder/decoder for bigf5 cookies

import argparse
import sys

# Constants
COLORS = {
    "blue": "\033[1;34m",
    "green": "\033[1;32m",
    "red": "\033[1;31m",
    "yellow": "\033[1;33m",
    "reset": "\033[0m"
}
SYMBOLS = {
    "plus": f"{COLORS['blue']}[{COLORS['reset']}{COLORS['green']}+{COLORS['reset']}{COLORS['blue']}]",
    "minus": f"{COLORS['blue']}[{COLORS['reset']}{COLORS['red']}-{COLORS['reset']}{COLORS['blue']}]",
    "cross": f"{COLORS['blue']}[{COLORS['reset']}{COLORS['red']}x{COLORS['reset']}{COLORS['blue']}]",
    "star": f"{COLORS['blue']}[*]{COLORS['reset']}",
    "warn": f"{COLORS['blue']}[{COLORS['reset']}{COLORS['yellow']}!{COLORS['reset']}{COLORS['blue']}]",
    "end": f"{COLORS['reset']}"
}

# Print the banner with some information about the script
def banner():
    banner_text = f"""
    {COLORS['yellow']}
    
    ┳┓•  ┏┓┏━  ┏┓   ┓    
    ┣┫┓┏┓┣ ┗┓━━┃ ┏┓┏┫┏┓┓┏
    ┻┛┗┗┫┻ ┗┛  ┗┛┗┛┗┻┗ ┛┗
        ┛                                                             
    
    @BeeSec
    Helping you Bee Secure
     
    {COLORS['reset']}
    """
    print(banner_text)

def encode_ipv4_address(ip):
    octets = ip.split('.')
    if len(octets) != 4:
        raise ValueError(f"{SYMBOLS['cross']} Invalid IP address format. Please use x.x.x.x format.")
    
    encoded_value = int(octets[0]) + int(octets[1]) * 256 + int(octets[2]) * 256 ** 2 + int(octets[3]) * 256 ** 3
    return encoded_value

def decode_ipv4_address(encoded_value):
    a = encoded_value % 256
    encoded_value //= 256
    b = encoded_value % 256
    encoded_value //= 256
    c = encoded_value % 256
    d = encoded_value // 256
    return f"{a}.{b}.{c}.{d}"

def encode_port(port):
    if not (0 <= port <= 65535):
        raise ValueError(f"{SYMBOLS['cross']} Invalid port value. Port must be between 0 and 65535.")
    hex_value = format(port, '04X')
    return int(hex_value, 16)

def decode_port(encoded_value):
    port_hex = format(encoded_value, '04X')
    port = int(port_hex, 16)
    return port

def main():
    banner()
    parser = argparse.ArgumentParser(description="Encode/Decode F5 Load Balancer cookie values")
    parser.add_argument("--encode-ip", help="Encode IP address in F5 cookie format")
    parser.add_argument("--encode-port", type=int, help="Encode port in F5 cookie format")
    parser.add_argument("-d", "--decode-cookie", help="Decode F5 cookie value to IP and port")

    args = parser.parse_args()

    if not any(vars(args).values()):
        parser.print_help()
        sys.exit(1)

    try:
        if args.encode_ip and args.encode_port:
            encoded_ip = encode_ipv4_address(args.encode_ip)
            encoded_port = encode_port(args.encode_port)
            encoded_cookie = f"{encoded_ip}.{encoded_port:04X}"
            print(f"{SYMBOLS['plus']} Encoded Cookie Value: {encoded_cookie}")

        elif args.decode_cookie:
            cookie_parts = args.decode_cookie.split('.')
            
            if len(cookie_parts) == 2:
                encoded_ip = int(cookie_parts[0])
                encoded_port = int(cookie_parts[1], 16)
                decoded_ip = decode_ipv4_address(encoded_ip)
                decoded_port = decode_port(encoded_port)
                print(f"{SYMBOLS['plus']} Decoded IP: {decoded_ip}")
                print(f"{SYMBOLS['plus']} Decoded Port: {decoded_port}")
            elif len(cookie_parts) == 3:
                decoded_ip = decode_ipv4_address(int(cookie_parts[0]))
                decoded_port = int(cookie_parts[1])
                print(f"{SYMBOLS['plus']} Decoded IP: {decoded_ip}")
                print(f"{SYMBOLS['plus']} Decoded Port: {decoded_port}")
            else:
                raise ValueError(f"{SYMBOLS['cross']} Invalid cookie value format. Please use 'ip.port' or 'ip.port.hex' format.")

    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
