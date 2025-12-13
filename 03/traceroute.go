package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type portDispatcher struct {
	// sync.Mutex是结构体字段，值接收者方法里嵌入字段即可；无须指针字段
	mu sync.Mutex // 这是go提供的互斥锁原语，实际不保护任何数据，需要用户自行遵守互斥锁的规范

	sinks map[int]chan<- string // 表示key是int，value是“只能写”的string chan
}

func newPortDispatcher() *portDispatcher {
	return &portDispatcher{sinks: make(map[int]chan<- string)}
}

// 这是go的method定义语法，本质是为p实现.register()的语法糖，实际效果等价为
// func register(p *portDispatcher, port int, ch chan<- string)
func (p *portDispatcher) register(port int, ch chan<- string) {
	// defer调用是按栈执行的；对称加锁/解锁最常见写法
	p.mu.Lock() // 这里p类型不管是值还是指针，都可以用.方法，按照C的语法理解就是.运算符重载了.和->
	defer p.mu.Unlock()
	p.sinks[port] = ch
}

func (p *portDispatcher) unregister(port int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.sinks, port)
}

func (p *portDispatcher) dispatch(port int, addr string) { // 就是根据port往指定channel塞string
	p.mu.Lock()
	ch := p.sinks[port]
	p.mu.Unlock()
	if ch != nil {
		ch <- addr
	}
}

type resultStore struct {
	mu    sync.Mutex
	hops  map[int][]string
	count int
}

func newResultStore(maxTTL int) *resultStore {
	return &resultStore{
		hops:  make(map[int][]string, maxTTL),
		count: maxTTL,
	}
}

func (r *resultStore) add(ttl int, addrs []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.hops[ttl] = append(r.hops[ttl], addrs...)
}

func (r *resultStore) get(ttl int) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	src := r.hops[ttl]
	dst := make([]string, len(src))
	copy(dst, src)
	return dst
}

func listenICMP(ctx context.Context, conn net.PacketConn, dispatcher *portDispatcher) {
	defer conn.Close()

	buf := make([]byte, 1500)
	for {
		// ReadDeadline可以让阻塞Read在超时后返回超时错误；避免goroutine永远阻塞
		_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				select {
				case <-ctx.Done():
					return
				default:
					continue
				}
			}
			log.Printf("icmp read error: %v", err)
			continue
		}
		srcPort, err := extractUDPSrcPort(buf[:n])
		if err != nil {
			log.Printf("extractUDPSrcPort error: %v", err)
			continue
		}
		dispatcher.dispatch(srcPort, addr.String())
	}
}

func extractUDPSrcPort(b []byte) (int, error) {
	pkt := gopacket.NewPacket(b, layers.LayerTypeICMPv4, gopacket.Default)
	icmpLayer := pkt.Layer(layers.LayerTypeICMPv4)
	if icmpLayer == nil {
		return 0, fmt.Errorf("no icmp layer in: %X", b)
	}
	icmp := icmpLayer.(*layers.ICMPv4)

	innerpkt := gopacket.NewPacket(icmp.Payload, layers.LayerTypeIPv4, gopacket.Default)
	innerIPLayer := innerpkt.Layer(layers.LayerTypeIPv4)
	if innerIPLayer == nil {
		return 0, fmt.Errorf("illegal icmp payload")
	}
	innerIP := innerIPLayer.(*layers.IPv4)
	if innerIP.Protocol != layers.IPProtocolUDP {
		return 0, fmt.Errorf("icmp payload ip is not UDP")
	}

	udpLayer := innerpkt.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return 0, fmt.Errorf("udp layer missing")
	}
	udp := udpLayer.(*layers.UDP)
	return int(udp.SrcPort), nil
}

func probeTTL(ctx context.Context, ttl int, probes int, basePayload int, timeout time.Duration, target *net.IPAddr, basePort int, dispatcher *portDispatcher, results *resultStore) {
	conn, err := dialUDPWithTTL(ttl, target.IP.String(), basePort+ttl)
	if err != nil {
		log.Printf("ttl=%d dial error: %v", ttl, err)
		return
	}
	defer conn.Close()

	// 类型断言：接口值.(具体类型)，第二个返回值bool表示断言是否成功
	localUDP, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		log.Printf("ttl=%d unexpected local addr type", ttl)
		return
	}

	respCh := make(chan string, probes*2)      // make第二个参数用在这里指chan的缓冲区大小
	dispatcher.register(localUDP.Port, respCh) // 建立 port-ch 映射
	defer dispatcher.unregister(localUDP.Port)

	payload := bytes.Repeat([]byte{0}, basePayload)
	for i := 0; i < probes; i++ {
		_ = conn.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
		if _, err := conn.Write(payload); err != nil {
			log.Printf("ttl=%d send error: %v", ttl, err)
		}
	}

	deadline := time.NewTimer(timeout)
	defer deadline.Stop()

	var routers []string
	for len(routers) < probes {
		select {
		case addr := <-respCh:
			routers = append(routers, addr)
		case <-deadline.C:
			results.add(ttl, routers)
			return
		case <-ctx.Done():
			results.add(ttl, routers)
			return
		}
	}
	results.add(ttl, routers)
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

func main() {
	// ---------------------------------
	//           Parse Args
	// ---------------------------------
	maxTTL := flag.Int("max-ttl", 30, "maximum TTL to probe")
	probes := flag.Int("probes", 3, "number of probes per TTL")
	basePayload := flag.Int("payload", 32, "base payload length")
	timeout := flag.Duration("timeout", 2*time.Second, "wait time per TTL")
	basePort := flag.Int("dport", 33434, "base destination UDP port")
	flag.Parse()

	if flag.NArg() != 1 { // NArg 返回传入的非flag参数量（位置参数）
		fmt.Fprintf(os.Stderr, "usage: %s [options] <host>\n", os.Args[0])
		flag.PrintDefaults()
		os.Exit(1)
	}
	target := flag.Arg(0)

	// ---------------------------------
	//          Domain Resolve
	// ---------------------------------
	ip, err := net.ResolveIPAddr("ip4", target) // net.ResolveIPAddr 接收IP直接返回，接收domain会解析
	if err != nil {
		log.Fatalf("resolve target: %v", err)
	}
	fmt.Printf("Traceroute to %s(%s)\n", target, ip)

	// ---------------------------------
	//          ICMP Listening
	// ---------------------------------
	icmpConn, err := net.ListenPacket("ip4:icmp", "0.0.0.0") // 创建接收
	if err != nil {
		log.Fatalf("listen icmp: %v", err)
	}

	// context库用于在goroutine间传递取消、超时、截止信号
	// 调用cancel()时，这个ctx 会被“标记为已取消”
	// 用于和select, <-ctx.Done() 结合完成取消通知
	// cancel可以被调用多次，推荐defer cancel() + 手动cancel()
	// 一旦 ctx 被取消，ctx.Done() 对应的 channel 会被关闭；
	// 对“已关闭 channel”的接收操作，永远不会阻塞。
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dispatcher := newPortDispatcher()
	go listenICMP(ctx, icmpConn, dispatcher)

	results := newResultStore(*maxTTL)

	// ---------------------------------
	//          Send UDP
	// ---------------------------------
	// 并发n个goroutine同时执行一段代码，并等待它们运行结束的模板
	// var wg sync.WaitGroup
	// for a := 1; a <= amax; a++ {
	// 	wg.Add(1)
	// 	go func(t int) {
	// 		defer wg.Done()
	// 		...
	// 	}(a)
	// }
	// wg.Wait()

	var wg sync.WaitGroup
	for ttl := 1; ttl <= *maxTTL; ttl++ {
		wg.Add(1)
		go func(t int) {
			defer wg.Done()
			probeTTL(ctx, t, *probes, *basePayload, *timeout, ip, *basePort, dispatcher, results)
		}(ttl) // 函数字面量捕获变量时要传参；否则会闭包共享同一个循环变量
	}
	wg.Wait()
	cancel()

	for ttl := 1; ttl <= *maxTTL; ttl++ {
		hops := dedup(results.get(ttl))
		if len(hops) == 0 {
			fmt.Printf("%2d  *\n", ttl)
			continue
		}
		fmt.Printf("%2d  %s\n", ttl, formatHops(hops))
	}
}

func formatHops(hops []string) string {
	return strings.Join(hops, "  ")
}
