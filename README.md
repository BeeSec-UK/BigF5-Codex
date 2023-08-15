# BigF5-Codex
An encoder/decoder for Bigf5 cookies; Internal IP information leakage

usage: bigf5-codex.py [-h] [--encode-ip ENCODE_IP] [--encode-port ENCODE_PORT] [-d DECODE_COOKIE]

Encode/Decode F5 Load Balancer cookie values

options:
  -h, --help            show this help message and exit
  
  --encode-ip ENCODE_IP
      Encode IP address in F5 cookie format
                        
  --encode-port ENCODE_PORT
    Encode port in F5 cookie format
                        
  -d DECODE_COOKIE, --decode-cookie DECODE_COOKIE
    Decode F5 cookie value to IP and port
                        
