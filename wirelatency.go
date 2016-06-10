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

func wl_track_int64(units string, value int64, name string) {
	if metrics != nil {
		metrics.SetHistogramValue(name, float64(value))
	}
}
func wl_track_float64(units string, value float64, name string) {
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
	Factory(port layers.TCPPort, inbound bool, config *string) tcpassembly.StreamFactory
}

type twoWayAssembly struct {
	proto   *WireLatencyTCPProtocol
	Config  *string
	in, out *tcpassembly.Assembler
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

	streamFactory_in := (*wp).Factory(port, true, config)
	streamPool_in := tcpassembly.NewStreamPool(streamFactory_in)
	assembly_in := tcpassembly.NewAssembler(streamPool_in)
	streamFactory_out := (*wp).Factory(port, false, config)
	streamPool_out := tcpassembly.NewStreamPool(streamFactory_out)
	assembly_out := tcpassembly.NewAssembler(streamPool_out)
	portAssemblerMap[port] = &twoWayAssembly{
		proto:  wp,
		in:     assembly_in,
		out:    assembly_out,
		Config: config,
	}
	return nil
}

var iface = flag.String("iface", "auto", "Select the system interface to sniff")
var debug_capture = flag.Bool("debug_capture", false, "Debug packet capture")

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
				if ip.IsGlobalUnicast() && ip.To4() != nil {
					if *iface == "auto" {
						choice = *try_iface
						iface = &choice
					}
				}
			}
		}
	}
	return *iface
}
func Capture() {
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

	flushDuration := 2 * time.Minute

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
			for _, assembly := range portAssemblerMap {
				assembly.in.FlushOlderThan(time.Now().Add(flushDuration))
				assembly.out.FlushOlderThan(time.Now().Add(flushDuration))
			}

		case packet := <-packets:
			if packet == nil {
				return
			}
			if packet.NetworkLayer() == nil || packet.TransportLayer() == nil || packet.TransportLayer().LayerType() != layers.LayerTypeTCP {
				continue
			}
			tcp := packet.TransportLayer().(*layers.TCP)
			var assembler *tcpassembly.Assembler
			if assembly, ok := portAssemblerMap[tcp.SrcPort]; ok {
				assembler = assembly.out
			}
			if assembly, ok := portAssemblerMap[tcp.DstPort]; ok {
				assembler = assembly.in
			}
			if assembler != nil {
				assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)
			}
		}
	}
}
