"""A fake internet for the Linux container: every name resolves to us, every TCP connection lands
here, and we keep what was asked for and what was sent. Nothing is forwarded anywhere."""
from __future__ import annotations

import socket
import socketserver
import struct
import threading
import time

SO_ORIGINAL_DST = 80
MAX_CAPTURE = 256 * 1024


def parse_qname(packet: bytes) -> tuple[str, int, int] | None:
    """(name, qtype, end offset) of the first question."""
    if len(packet) < 12:
        return None
    i, labels = 12, []
    while i < len(packet):
        n = packet[i]
        if n == 0:
            i += 1
            break
        if n & 0xC0 or i + 1 + n > len(packet):
            return None
        labels.append(packet[i + 1 : i + 1 + n].decode('ascii', 'replace'))
        i += 1 + n
    if i + 4 > len(packet):
        return None
    qtype = struct.unpack('>H', packet[i : i + 2])[0]
    return '.'.join(labels).lower(), qtype, i + 4


def dns_answer(packet: bytes, ip: str) -> bytes | None:
    q = parse_qname(packet)
    if not q:
        return None
    name, qtype, end = q
    head = packet[:2] + b'\x81\x80' + packet[4:6]
    question = packet[12:end]
    if qtype == 1:  # A: point everything at the sinkhole
        answer = b'\xc0\x0c' + struct.pack('>HHIH', 1, 1, 30, 4) + socket.inet_aton(ip)
        return head + struct.pack('>HHH', 1, 0, 0) + question + answer
    return head + struct.pack('>HHH', 0, 0, 0) + question


def tls_sni(data: bytes) -> str | None:
    try:
        if data[0] != 0x16 or data[5] != 0x01:
            return None
        i = 43
        i += 1 + data[i]
        i += 2 + struct.unpack('>H', data[i : i + 2])[0]
        i += 1 + data[i]
        end = i + 2 + struct.unpack('>H', data[i : i + 2])[0]
        i += 2
        while i + 4 <= end:
            etype, elen = struct.unpack('>HH', data[i : i + 4])
            if etype == 0:
                n = struct.unpack('>H', data[i + 7 : i + 9])[0]
                return data[i + 9 : i + 9 + n].decode('ascii', 'replace').lower()
            i += 4 + elen
    except (IndexError, struct.error):
        return None
    return None


def http_host(data: bytes) -> str | None:
    if not data[:8].split(b' ')[0] in (b'GET', b'POST', b'PUT', b'HEAD', b'PATCH', b'DELETE', b'OPTIONS', b'CONNECT'):
        return None
    for line in data.split(b'\r\n')[1:40]:
        if line.lower().startswith(b'host:'):
            return line[5:].strip().decode('ascii', 'replace').split(':')[0].lower()
    return None


class Sinkhole:
    def __init__(self, ip: str, dns_port: int = 5353, tcp_port: int = 9999):
        self.ip = ip
        self.dns_port = dns_port
        self.tcp_port = tcp_port
        self.lock = threading.Lock()
        self.queries: list[tuple[float, str]] = []
        self.connections: list[dict] = []
        self.payloads: list[tuple[str, bytes]] = []

    def start(self) -> None:
        sink = self

        class Dns(socketserver.BaseRequestHandler):
            def handle(self):
                data, sock = self.request
                q = parse_qname(data)
                if q:
                    with sink.lock:
                        sink.queries.append((time.time(), q[0]))
                        sink.payloads.append((f'DNS {q[0]}', q[0].encode()))
                reply = dns_answer(data, sink.ip)
                if reply:
                    sock.sendto(reply, self.client_address)

        class Tcp(socketserver.BaseRequestHandler):
            def handle(self):
                conn: socket.socket = self.request
                try:
                    raw = conn.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
                    port = struct.unpack('>H', raw[2:4])[0]
                    dst = socket.inet_ntoa(raw[4:8])
                except OSError:
                    dst, port = '?', 0
                conn.settimeout(4)
                data = b''
                try:
                    while len(data) < MAX_CAPTURE:
                        chunk = conn.recv(65536)
                        if not chunk:
                            break
                        data += chunk
                        if data[:1] == b'\x16':
                            break  # a TLS hello: we can't answer it, the name is all we get
                        if http_host(data) and b'\r\n\r\n' in data:
                            head, _, body = data.partition(b'\r\n\r\n')
                            length = next((int(l.split(b':')[1]) for l in head.split(b'\r\n') if l.lower().startswith(b'content-length:') and l.split(b':')[1].strip().isdigit()), 0)
                            if len(body) >= min(length, MAX_CAPTURE):
                                conn.sendall(b'HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
                                break
                except OSError:
                    pass
                finally:
                    conn.close()
                now = time.time()
                with sink.lock:
                    recent = [n for t, n in sink.queries if now - t < 10]
                    sink.connections.append({
                        'ip': dst, 'port': port, 'proto': 'tcp', 'sni': tls_sni(data), 'http': http_host(data),
                        'host': (recent[-1] if recent and dst == sink.ip else None),
                    })
                    sink.payloads.append((f'{dst}:{port}', data))

        socketserver.ThreadingUDPServer.allow_reuse_address = True
        socketserver.ThreadingTCPServer.allow_reuse_address = True
        self.udp = socketserver.ThreadingUDPServer((self.ip, self.dns_port), Dns)
        self.tcp = socketserver.ThreadingTCPServer((self.ip, self.tcp_port), Tcp)
        self.udp.daemon_threads = self.tcp.daemon_threads = True
        threading.Thread(target=self.udp.serve_forever, daemon=True).start()
        threading.Thread(target=self.tcp.serve_forever, daemon=True).start()

    def stop(self) -> None:
        for s in (getattr(self, 'udp', None), getattr(self, 'tcp', None)):
            if s:
                s.shutdown()
                s.server_close()
