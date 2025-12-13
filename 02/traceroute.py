import util

# Your program should send TTLs in the range [1, TRACEROUTE_MAX_TTL] inclusive.
# Technically IPv4 supports TTLs up to 255, but in practice this is excessive.
# Most traceroute implementations cap at approximately 30.  The unit tests
# assume you don't change this number.
TRACEROUTE_MAX_TTL = 30

# Cisco seems to have standardized on UDP ports [33434, 33464] for traceroute.
# While not a formal standard, it appears that some routers on the internet
# will only respond with time exceeeded ICMP messages to UDP packets send to
# those ports.  Ultimately, you can choose whatever port you like, but that
# range seems to give more interesting results.
TRACEROUTE_PORT_NUMBER = 33434  # Cisco traceroute port number.

# Sometimes packets on the internet get dropped.  PROBE_ATTEMPT_COUNT is the
# maximum number of times your traceroute function should attempt to probe a
# single router before giving up and moving on.
PROBE_ATTEMPT_COUNT = 3

class IPv4:
    # Each member below is a field from the IPv4 packet header.  They are
    # listed below in the order they appear in the packet.  All fields should
    # be stored in host byte order.
    #
    # You should only modify the __init__() method of this class.
    version: int
    header_len: int  # Note length in bytes, not the value in the packet.
    tos: int         # Also called DSCP and ECN bits (i.e. on wikipedia).
    length: int      # Total length of the packet.
    id: int
    flags: int
    frag_offset: int
    ttl: int
    proto: int
    cksum: int
    src: str
    dst: str
    payload: bytes

    def __init__(self, buffer: bytes):
        self.version = int(buffer[0] >> 4)
        self.header_len = int(buffer[0] & 0b1111)
        self.tos = int(buffer[1])
        self.length = int.from_bytes(buffer[2:4], byteorder="big")
        self.id = int.from_bytes(buffer[4:6], byteorder="big")
        self.flags = int(buffer[6] >> 5)
        self.frag_offset = int.from_bytes(buffer[6:8], byteorder="big") & 0b1_1111_1111_1111
        self.ttl = int(buffer[8])
        self.proto = int(buffer[9])
        self.cksum = int.from_bytes(buffer[10:12], byteorder="big")
        self.src = ".".join([str(int(byte)) for byte in buffer[12:16]])
        self.dst = ".".join([str(int(byte)) for byte in buffer[16:20]])
        self.payload = buffer[self.header_len*4:self.length]
        

    def __str__(self) -> str:
        return f"IPv{self.version} (tos 0x{self.tos:x}, ttl {self.ttl}, " + \
            f"id {self.id}, flags 0x{self.flags:x}, " + \
            f"ofsset {self.frag_offset}, " + \
            f"proto {self.proto}, header_len {self.header_len}, " + \
            f"len {self.length}, cksum 0x{self.cksum:x}) " + \
            f"{self.src} > {self.dst}"


class ICMP:
    # Each member below is a field from the ICMP header.  They are listed below
    # in the order they appear in the packet.  All fields should be stored in
    # host byte order.
    #
    # You should only modify the __init__() function of this class.
    type: int
    code: int
    cksum: int
    rest: bytes
    payload: bytes

    def __init__(self, buffer: bytes):
        self.type = int(buffer[0])
        self.code = int(buffer[1])
        self.cksum = int.from_bytes(buffer[2:4], byteorder="big")
        self.rest = buffer[4:8]
        self.payload = buffer[8:]

    def __str__(self) -> str:
        return f"ICMP (type {self.type}, code {self.code}, " + \
            f"cksum 0x{self.cksum:x})"


class UDP:
    # Each member below is a field from the UDP header.  They are listed below
    # in the order they appear in the packet.  All fields should be stored in
    # host byte order.
    #
    # You should only modify the __init__() function of this class.
    src_port: int
    dst_port: int
    len: int
    cksum: int

    def __init__(self, buffer: bytes):
        self.src_port = int.from_bytes(buffer[0:2], byteorder="big")
        self.dist_port = int.from_bytes(buffer[2:4], byteorder="big")
        self.len = int.from_bytes(buffer[4:6], byteorder="big")
        self.cksum = int.from_bytes(buffer[6:8], byteorder="big")

    def __str__(self) -> str:
        return f"UDP (src_port {self.src_port}, dst_port {self.dst_port}, " + \
            f"len {self.len}, cksum 0x{self.cksum:x})"

# TODO feel free to add helper functions if you'd like

def traceroute(sendsock: util.Socket, recvsock: util.Socket, ip: str) \
        -> list[list[str]]:
    """ Run traceroute and returns the discovered path.

    Calls util.print_result() on the result of each TTL's probes to show
    progress.

    Arguments:
    sendsock -- This is a UDP socket you will use to send traceroute probes.
    recvsock -- This is the socket on which you will receive ICMP responses.
    ip -- This is the IP address of the end host you will be tracerouting.

    Returns:
    A list of lists representing the routers discovered for each ttl that was
    probed.  The ith list contains all of the routers found with TTL probe of
    i+1.   The routers discovered in the ith list can be in any order.  If no
    routers were found, the ith list can be empty.  If `ip` is discovered, it
    should be included as the final element in the list.
    """

    routerlists = []
    
    for ttl in range(1, TRACEROUTE_MAX_TTL+1):
        sendsock.set_ttl(ttl)
        sendsock.sendto("Hello".encode(), (ip, TRACEROUTE_PORT_NUMBER))
        routers = []
        found = False
        for _ in range(PROBE_ATTEMPT_COUNT):
            if found:
                break
            # sleep(1)
            if recvsock.recv_select():
                ip_icmp_pack, (router_ip, _) = recvsock.recvfrom()
                print(ip_icmp_pack.hex())
                ipv4_pack = IPv4(ip_icmp_pack)
                print(ipv4_pack)
                if ipv4_pack.proto == 1: # ICMP
                    icmp_pack = ICMP(ipv4_pack.payload)
                    if icmp_pack.code == 0: # TTL exceeded
                        sendpack = IPv4(icmp_pack.payload)
                        if sendpack.proto == 17: # UDP
                            routers.append(router_ip)
                    elif icmp_pack.code == 3: # Destination Port Unreachable
                        found = True
                        routers.append(ip)
                        break
                    else:
                        print("qwqwqwq")

        routerlists.append(routers)
        util.print_result(routerlists[ttl-1], ttl)

        

    return routerlists


if __name__ == '__main__':
    args = util.parse_args()
    ip_addr = util.gethostbyname(args.host)
    print(f"traceroute to {args.host} ({ip_addr})")
    traceroute(util.Socket.make_udp(), util.Socket.make_icmp(), ip_addr)
