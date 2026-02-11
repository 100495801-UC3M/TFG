import socket

HOST = "127.0.0.1"
PORT = 8080


def send(number, phrase):
    # The server expects NUL-separated arguments (C-style strings).
    # Build a bytes payload: "RPC_BUILD\0<number>\0<phrase>\0"
    part_cmd = b"RPC_BUILD"
    part_num = str(number).encode()
    part_phrase = phrase.encode()
    msg = part_cmd + b"\x00" + part_num + b"\x00" + part_phrase + b"\x00"

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        s.sendall(msg)
        # Receive up to 4KB; server sends two NUL-terminated strings (phrase, number*5)
        raw = s.recv(4096)
        if not raw:
            return None

        # Split on NUL bytes and filter empty parts
        parts = [p for p in raw.split(b'\x00') if len(p) > 0]
        decoded = []
        for p in parts:
            try:
                s = p.decode()
            except Exception:
                s = p.decode('latin-1')
            # Try to convert numeric-looking strings to int for convenience
            try:
                if s.isdigit() or (s.startswith('-') and s[1:].isdigit()):
                    decoded.append(int(s))
                else:
                    decoded.append(s)
            except Exception:
                decoded.append(s)

        # If server returned one part, keep compatibility and return string
        if len(decoded) == 1:
            return decoded[0]
        # If server returned multiple parts, return tuple (phrase, number5, ...)
        return tuple(decoded)
