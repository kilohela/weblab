package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// ttlResult按TTL存放路由器地址列表；索引0空置，便于直接按TTL访问
type ttlResult [][]string

func newTTLResult(maxTTL int) ttlResult {
	return make([][]string, maxTTL+1)
}

// ttlState 记录每个TTL发送开始时间和已收到的响应数
type ttlState struct {
	start    time.Time
	received int
}

// parseICMP复用gopacket解出内层UDP的目的端口（用于反查TTL）
func parseICMP(b []byte) (int, string, error) {
	pkt := gopacket.NewPacket(b, layers.LayerTypeICMPv4, gopacket.Default)
	icmpLayer := pkt.Layer(layers.LayerTypeICMPv4)
	if icmpLayer == nil {
		return 0, "", fmt.Errorf("no icmp layer")
	}
	icmp := icmpLayer.(*layers.ICMPv4)
	isTTLExceeded := icmp.TypeCode.Type() == layers.ICMPv4TypeTimeExceeded && icmp.TypeCode.Code() == 0
	isPortUnreachable := icmp.TypeCode.Type() == layers.ICMPv4TypeDestinationUnreachable && icmp.TypeCode.Code() == 3
	if !isTTLExceeded && !isPortUnreachable {
		return 0, "", fmt.Errorf("unsupported icmp type/code: %v", icmp.TypeCode)
	}

	innerpkt := gopacket.NewPacket(icmp.Payload, layers.LayerTypeIPv4, gopacket.Default)
	innerIPLayer := innerpkt.Layer(layers.LayerTypeIPv4)
	if innerIPLayer == nil {
		return 0, "", fmt.Errorf("illegal icmp payload")
	}
	innerIP := innerIPLayer.(*layers.IPv4)
	if innerIP.Protocol != layers.IPProtocolUDP {
		return 0, "", fmt.Errorf("icmp payload ip is not UDP")
	}

	udpLayer := innerpkt.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return 0, "", fmt.Errorf("udp layer missing")
	}
	udp := udpLayer.(*layers.UDP)

	// 外层ICMP包的源地址就是路由器地址
	if ipLayer := pkt.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		if ip := ipLayer.(*layers.IPv4); ip != nil {
			router := ip.SrcIP.String()
			if isPortUnreachable {
				router += " destination"
			}
			return int(udp.DstPort), router, nil
		}
	}
	return int(udp.DstPort), "", nil
}

func dialUDPWithTTL(ttl int, ip string, port int) (*net.UDPConn, error) {
	dialer := net.Dialer{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TTL, ttl)
			})
		},
		Timeout: 2 * time.Second,
	}
	conn, err := dialer.Dial("udp4", fmt.Sprintf("%s:%d", ip, port))
	if err != nil {
		return nil, err
	}
	if udpConn, ok := conn.(*net.UDPConn); ok {
		return udpConn, nil
	}
	_ = conn.Close()
	return nil, fmt.Errorf("unexpected conn type")
}

// dedup保留出现顺序，移除重复项
func dedup(items []string) []string {
	seen := make(map[string]struct{}, len(items))
	out := make([]string, 0, len(items))
	for _, it := range items {
		if _, ok := seen[it]; ok {
			continue
		}
		seen[it] = struct{}{}
		out = append(out, it)
	}
	return out
}

func formatHops(hops []string) string {
	return strings.Join(hops, "  ")
}

func main() {
	maxTTL := flag.Int("max-ttl", 30, "maximum TTL to probe")
	probes := flag.Int("probes", 3, "number of probes per TTL")
	basePayload := flag.String("payload", "Hello", "payload content")
	timeout := flag.Duration("timeout", 2*time.Second, "wait time per TTL")
	basePort := flag.Int("dport", 33434, "base destination UDP port")
	flag.Parse()

	if flag.NArg() != 1 { // NArg 返回传入的非flag参数量（位置参数）
		fmt.Fprintf(os.Stderr, "usage: %s [options] <host>\n", os.Args[0])
		flag.PrintDefaults()
		os.Exit(1)
	}
	target := flag.Arg(0)

	ip, err := net.ResolveIPAddr("ip4", target)
	if err != nil {
		log.Fatalf("resolve target: %v", err)
	}
	fmt.Printf("Traceroute to %s(%s)\n", target, ip)

	// 先创建ICMP监听，后续读写都围绕这一个socket
	icmpConn, err := net.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		log.Fatalf("listen icmp: %v", err)
	}
	defer icmpConn.Close()

	// port->ttl映射，用发送阶段记录，接收阶段反查；使用目的端口唯一标识每个TTL
	portTTL := make(map[int]int, *maxTTL)
	results := newTTLResult(*maxTTL)
	state := make([]ttlState, *maxTTL+1)

	// 非阻塞遍历TTL，逐一发送UDP探测
	for ttl := 1; ttl <= *maxTTL; ttl++ {
		dstPort := *basePort + ttl
		conn, err := dialUDPWithTTL(ttl, ip.IP.String(), dstPort)
		if err != nil {
			log.Printf("ttl=%d dial error: %v", ttl, err)
			continue
		}
		portTTL[dstPort] = ttl
		state[ttl] = ttlState{start: time.Now()}

		payload := []byte(*basePayload)
		for i := 0; i < *probes; i++ {
			_ = conn.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
			if _, err := conn.Write(payload); err != nil {
				log.Printf("ttl=%d send error: %v", ttl, err)
			}
		}
		_ = conn.Close()
	}

	// 不断从icmp socket读取；根据portTTL反推是哪个TTL的响应
	buf := make([]byte, 1500)
	// 总等待时间上界：每个TTL timeout，各自起始时间不同，所以循环通过“全部TTL都超时或收满”判定退出
	for {
		_ = icmpConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, addr, err := icmpConn.ReadFrom(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if allTTLFinished(state, *probes, *timeout) {
					break
				}
				continue
			}
			log.Printf("icmp read error: %v", err)
			continue
		}

		dstPort, routerIP, err := parseICMP(buf[:n])
		if err != nil {
			log.Printf("parse icmp error: %v", err)
			continue
		}
		ttl, ok := portTTL[dstPort]
		if !ok {
			// 未知端口，忽略
			continue
		}
		if routerIP == "" { // 回退用addr
			routerIP = addr.String()
		}
		results[ttl] = append(results[ttl], routerIP)
		state[ttl].received++
		if allTTLFinished(state, *probes, *timeout) {
			break
		}
	}

	for ttl := 1; ttl <= *maxTTL; ttl++ {
		hops := dedup(results[ttl])
		if len(hops) == 0 {
			fmt.Printf("%2d  *\n", ttl)
			continue
		}
		fmt.Printf("%2d  %s\n", ttl, formatHops(hops))
	}
}

func allTTLFinished(state []ttlState, probes int, timeout time.Duration) bool {
	now := time.Now()
	for ttl := 1; ttl < len(state); ttl++ {
		s := state[ttl]
		if s.start.IsZero() {
			continue
		}
		if s.received < probes && now.Sub(s.start) < timeout {
			return false
		}
	}
	return true
}
