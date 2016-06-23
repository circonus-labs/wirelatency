package wirelatency

import (
	"errors"
	"flag"
	"github.com/circonus-labs/circonus-gometrics"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"log"
	"net"
	"runtime"
	"strconv"
	"time"
)

var metrics *circonusgometrics.CirconusMetrics
var debug_measurements = flag.Bool("debug_measurements", false, "Debug measurement recording")
var haveLocalAddresses bool = false
var localAddresses map[gopacket.Endpoint]bool = make(map[gopacket.Endpoint]bool)

func AddLocalIP(ip net.IP) {
	if ip.To4() != nil {
		haveLocalAddresses = true
		localAddresses[gopacket.NewEndpoint(layers.EndpointIPv4, ip.To4())] = true
	}
	if ip.To16() != nil {
		haveLocalAddresses = true
		localAddresses[gopacket.NewEndpoint(layers.EndpointIPv6, ip.To16())] = true
	}
}

func wl_track_int64(units string, value int64, name string) {
	if *debug_measurements {
		log.Printf("[METRIC] %s -> %d %s", name, value, units)
	}
	if metrics != nil {
		metrics.SetHistogramValue(name, float64(value))
	}
}
func wl_track_float64(units string, value float64, name string) {
	if *debug_measurements {
		log.Printf("[METRIC] %s -> %f %s", name, value, units)
	}
	if metrics != nil {
		metrics.SetHistogramValue(name, value)
	}
}

func SetMetrics(m *circonusgometrics.CirconusMetrics) {
	metrics = m
}

type WireLatencyTCPProtocol interface {
	Name() string
	DefaultPort() layers.TCPPort
	Factory(port layers.TCPPort, config *string) tcpassembly.StreamFactory
}

type twoWayAssembly struct {
	proto     *WireLatencyTCPProtocol
	assembler *tcpassembly.Assembler
	Config    *string
}

func (twa *twoWayAssembly) Proto() *WireLatencyTCPProtocol {
	return twa.proto
}

var portAssemblerMap = make(map[layers.TCPPort]*twoWayAssembly)
var protocols = make(map[string]*WireLatencyTCPProtocol)

func RegisterTCPProtocol(protocol WireLatencyTCPProtocol) {
	protocols[protocol.Name()] = &protocol
}

func RegisterTCPPort(port layers.TCPPort, protocolName string, config *string) error {
	wp, ok := protocols[protocolName]
	if !ok {
		return errors.New("bad protocol")
	}
	if port == 0 {
		port = (*wp).DefaultPort()
	}
	if _, exists := portAssemblerMap[port]; exists {
		return errors.New("port already mapped")
	}

	streamFactory := (*wp).Factory(port, config)
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)
	portAssemblerMap[port] = &twoWayAssembly{
		proto:     wp,
		assembler: assembler,
		Config:    config,
	}
	return nil
}

var flushAfter = flag.String("flush_after", "30s",
	"Connections with gaps will have buffered packets flushed after this timeout")

var iface = flag.String("iface", "auto", "Select the system interface to sniff")
var debug_capture_data = flag.Bool("debug_capture_data", false, "Debug packet capture data")
var debug_capture = flag.Bool("debug_capture", false, "Debug packet assembly")

func Protocols() map[string]*WireLatencyTCPProtocol {
	return protocols
}
func PortMap() map[layers.TCPPort]*twoWayAssembly {
	return portAssemblerMap
}
func selectInterface() string {
	choice := *iface
	ifaces, err := net.Interfaces()
	if err != nil {
		log.Fatal(err)
	}
	for _, iface_try := range ifaces {
		addrs, err := iface_try.Addrs()
		if err != nil {
			log.Printf("Error on interface: %v", iface_try.Name)
			continue
		}
		for _, ifi := range addrs {
			try_iface := &iface_try.Name
			if ip, _, _ := net.ParseCIDR(ifi.String()); ip != nil {
				if ip.IsGlobalUnicast() {
					if ip.To16() != nil {
						haveLocalAddresses = true
						localAddresses[gopacket.NewEndpoint(layers.EndpointIPv6, ip.To16())] = true
					}
					if ip.To4() != nil {
						haveLocalAddresses = true
						localAddresses[gopacket.NewEndpoint(layers.EndpointIPv4, ip.To4())] = true
						if *iface == "auto" {
							choice = *try_iface
							iface = &choice
						}
					}
				}
			}
		}
	}
	return *iface
}
func Capture() {
	flushDuration, err := time.ParseDuration(*flushAfter)
	if err != nil {
		log.Fatal("invalid flush duration: ", *flushAfter)
	}

	// Construct our BPF filter
	filter := "tcp and ("
	subsequent_or := ""
	for port := range portAssemblerMap {
		filter = filter + subsequent_or + "port " + strconv.Itoa(int(port))
		subsequent_or = " or "
	}
	filter = filter + ")"

	ifname := selectInterface()
	promisc := false
	if runtime.GOOS == "solaris" {
		promisc = true
	}
	if *debug_capture {
		pstr := " "
		if promisc {
			pstr = " [promiscuous] "
		}
		log.Printf("[DEBUG] Activating BPF%sfilter on %v: '%v'", pstr, ifname, filter)
	}
	handle, err := pcap.OpenLive(ifname, 65536, promisc, pcap.BlockForever)
	if err != nil {
		log.Fatal("error opening pcap handle: ", err)
	}
	if err := handle.SetBPFFilter(filter); err != nil {
		log.Fatal("error setting BPF filter: ", err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()
	ticker := time.Tick(flushDuration)

	for {
		select {
		case <-ticker:
			stats, _ := handle.Stats()
			if *debug_capture {
				log.Printf("[DEBUG] flushing all streams that haven't seen packets, pcap stats: %+v", stats)
			}
			for _, twa := range portAssemblerMap {
				twa.assembler.FlushOlderThan(time.Now().Add(0 - flushDuration))
			}

		case packet := <-packets:
			if packet == nil {
				return
			}
			if packet.NetworkLayer() == nil || packet.TransportLayer() == nil || packet.TransportLayer().LayerType() != layers.LayerTypeTCP {
				continue
			}
			tcp := packet.TransportLayer().(*layers.TCP)
			if twa, ok := portAssemblerMap[tcp.SrcPort]; ok {
				twa.assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)
			}
			if twa, ok := portAssemblerMap[tcp.DstPort]; ok {
				twa.assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)
			}
		}
	}
}
