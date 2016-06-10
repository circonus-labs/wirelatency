package wirelatency

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
	"log"
	"strconv"
	"sync/atomic"
	"time"
)

type tcpStreamFactory struct {
	interpFactory *TCPProtocolInterpreterFactory
	port          layers.TCPPort
	useReaders    bool
	n_clients     int64
	n_sessions    int64
	config        interface{}
}

const (
	sessionStateBlank = iota
	sessionStateGood  = iota
	sessionStateBad   = iota
)

type tcpTwoWayStream struct {
	factory *tcpStreamFactory
	interp  *TCPProtocolInterpreter
	in, out *tcpStream
	state   int
}

type tcpStream struct {
	inbound                             bool
	net, transport                      gopacket.Flow
	bytes, packets, outOfOrder, skipped int64
	start, end                          time.Time
	sawStart, sawEnd                    bool
	reader                              *tcpreader.ReaderStream
	parent                              *tcpTwoWayStream
}

var sessions = make(map[gopacket.Flow]map[gopacket.Flow]*tcpTwoWayStream)

func isLocalDst(e gopacket.Endpoint) bool {
	// If we have no local addresses we're busted and can't deny this is local
	if !haveLocalAddresses {
		return true
	}
	is_mine, _ := localAddresses[e]
	return is_mine
}
func (factory *tcpStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	inbound := transport.Dst().String() == strconv.Itoa(int(factory.port)) && isLocalDst(net.Dst())
	net_session := net
	transport_session := transport
	if !inbound {
		net_session = net.Reverse()
		transport_session = transport.Reverse()
	}

	// Setup the two level session hash
	// session[localnet:remotenet][localport:remoteport] -> &tcpTwoWayStream
	dsess, ok := sessions[net_session]
	if !ok {
		if *debug_capture {
			log.Printf("[DEBUG] establishing sessions for net:%v", net_session)
		}
		dsess = make(map[gopacket.Flow]*tcpTwoWayStream)
		sessions[net_session] = dsess
	}
	parent, pok := dsess[transport_session]
	if !pok {
		if *debug_capture {
			log.Printf("[DEBUG] establishing dsessions for ports:%v", transport_session)
		}
		interp := (*factory.interpFactory).New()
		parent = &tcpTwoWayStream{interp: &interp, factory: factory}
		dsess[transport_session] = parent
	}

	// Handle the inbound initial session startup
	if inbound {
		if *debug_capture {
			log.Printf("[DEBUG] new inbound TCP stream %v:%v started, paired: %v", net_session, transport_session, parent.out != nil)
		}
		atomic.AddInt64(&factory.n_clients, 1)
		atomic.AddInt64(&factory.n_sessions, 1)
		s := &tcpStream{
			inbound:   true,
			parent:    parent,
			net:       net,
			transport: transport,
			start:     time.Now(),
		}
		if factory.useReaders {
			r := tcpreader.NewReaderStream()
			s.reader = &r
		}
		parent.in = s
		s.end = s.start
		if factory.useReaders {
			go func() {
				(*parent.interp).ManageIn(parent)
				if *debug_capture {
					log.Printf("[DEBUG] go ManageIn(%v:%v) ended", s.net, s.transport)
				}
			}()
		}
		return s
	}

	if *debug_capture {
		log.Printf("[DEBUG] new outbound TCP stream %v:%v started, paired: %v", net_session, transport_session, parent.in != nil)
	}
	// The outbound return session startup
	s := &tcpStream{
		inbound:   false,
		parent:    parent,
		net:       net,
		transport: transport,
		start:     time.Now(),
	}
	if factory.useReaders {
		r := tcpreader.NewReaderStream()
		s.reader = &r
	}
	parent.out = s
	if factory.useReaders {
		go func() {
			(*parent.interp).ManageOut(parent)
			if *debug_capture {
				log.Printf("[DEBUG] go ManageOut(%v:%v) ended", s.net, s.transport)
			}
		}()
	}
	return s
}

func (s *tcpStream) Reassembled(reassemblies []tcpassembly.Reassembly) {
	if s.parent.state == sessionStateBad {
		if *debug_capture {
			log.Printf("[DEBUG] %v:%v in bad state", s.net, s.transport)
		}
		return
	}
	direction := "outbound"
	if s.inbound {
		direction = "inbound"
	}

	for _, reassembly := range reassemblies {
		if reassembly.Skip == 0 {
			if s.parent.in == s {
				if s.parent.state == sessionStateBlank {
					s.parent.state = sessionStateGood
				}
			}
		}
		if reassembly.Skip < 0 {
			s.parent.state = sessionStateBad
		} else if s.parent.state != sessionStateGood {
			s.parent.state = sessionStateBad
		}
		if reassembly.Seen.Before(s.end) {
			s.outOfOrder++
		} else {
			s.end = reassembly.Seen
		}
		s.bytes += int64(len(reassembly.Bytes))
		if s.parent.interp != nil {
			if *debug_capture_data {
				log.Printf("[DEBUG] %v %v", direction, reassembly.Bytes)
			}
			if s.parent.in == s {
				if !(*s.parent.interp).InBytes(reassembly.Seen, reassembly.Bytes) {
					s.parent.state = sessionStateBad
				}
			} else {
				if !(*s.parent.interp).OutBytes(reassembly.Seen, reassembly.Bytes) {
					s.parent.state = sessionStateBad
				}

			}
		}
		s.packets += 1
		if reassembly.Skip > 0 {
			s.skipped += int64(reassembly.Skip)
		}
		s.sawStart = s.sawStart || reassembly.Start
		s.sawEnd = s.sawEnd || reassembly.End
	}

	if s.reader != nil {
		s.reader.Reassembled(reassemblies)
	}
}
func (s *tcpStream) ReassemblyComplete() {
	if dsess, ok := sessions[s.net]; ok {
		if parent, ok := dsess[s.transport]; ok {
			if *debug_capture {
				log.Printf("[DEBUG] reassembly done %v:%v", s.net, s.transport)
			}
			if parent.in != nil && parent.in.reader != nil {
				atomic.AddInt64(&parent.factory.n_sessions, -1)
				parent.in.reader.ReassemblyComplete()
				parent.in.reader = nil
			}
			if parent.out != nil && parent.out.reader != nil {
				parent.out.reader.ReassemblyComplete()
				parent.out.reader = nil
			}
		}
		delete(dsess, s.transport)
		if len(dsess) == 0 {
			if *debug_capture {
				log.Printf("[DEBUG] removing session: %v:%v", s.net, s.transport)
			}
			delete(sessions, s.net)
		}
	}
}

type TCPProtocolInterpreter interface {
	ManageIn(stream *tcpTwoWayStream)
	ManageOut(stream *tcpTwoWayStream)
	InBytes(seen time.Time, bytes []byte) bool
	OutBytes(seen time.Time, bytes []byte) bool
}
type TCPProtocolInterpreterFactory interface {
	New() TCPProtocolInterpreter
}

type configbuilder func(*string) interface{}
type TCPProtocol struct {
	name          string
	defaultPort   layers.TCPPort
	useReaders    bool
	interpFactory TCPProtocolInterpreterFactory
	Config        configbuilder
}

func (p *TCPProtocol) Name() string {
	return (*p).name
}
func (p *TCPProtocol) DefaultPort() layers.TCPPort {
	return (*p).defaultPort
}
func (p *TCPProtocol) Factory(port layers.TCPPort, config *string) tcpassembly.StreamFactory {
	factory := &tcpStreamFactory{
		port:          port,
		useReaders:    p.useReaders,
		interpFactory: &p.interpFactory,
		config:        p.Config(config),
	}
	if metrics != nil {
		base := p.Name() + "`" + port.String()
		metrics.SetCounterFunc(base+"`total_sessions",
			func() uint64 { return uint64(factory.n_clients) })
		metrics.SetGaugeFunc(base+"`active_sessions",
			func() int64 { return factory.n_sessions })
	}
	return factory
}
