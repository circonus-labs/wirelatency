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
	inbound       bool
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
	net, transport                      gopacket.Flow
	bytes, packets, outOfOrder, skipped int64
	start, end                          time.Time
	sawStart, sawEnd                    bool
	reader                              *tcpreader.ReaderStream
	parent                              *tcpTwoWayStream
}

var sessions = make(map[gopacket.Flow]map[gopacket.Flow]*tcpTwoWayStream)

func (factory *tcpStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	if transport.Dst().String() == strconv.Itoa(int(factory.port)) && factory.inbound {
		if *debug_capture {
			log.Printf("[DEBUG] new TCP stream %v:%v started", net, transport)
		}
		atomic.AddInt64(&factory.n_clients, 1)
		atomic.AddInt64(&factory.n_sessions, 1)
		interp := (*factory.interpFactory).New()
		parent := &tcpTwoWayStream{interp: &interp, factory: factory}
		s := &tcpStream{
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
		dsess, ok := sessions[net]
		if !ok {
			dsess = make(map[gopacket.Flow]*tcpTwoWayStream)
			sessions[net] = dsess
		}
		dsess[transport] = parent
		s.end = s.start
		if factory.useReaders {
			go (*parent.interp).ManageIn(parent)
		}
		return s
	} else {
		if dsess, ok := sessions[net.Reverse()]; ok {
			if parent, pok := dsess[transport.Reverse()]; pok {
				s := &tcpStream{
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
					go (*parent.interp).ManageOut(parent)
				}
				return s
			}
		}
	}
	return nil
}

func (s *tcpStream) Reassembled(reassemblies []tcpassembly.Reassembly) {
	if s.parent.state == sessionStateBad {
		if *debug_capture {
			log.Printf("[DEBUG] %v:%v in bad state", s.net, s.transport)
		}
		return
	}
	direction := "outbound"
	if s.parent.in == s {
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
			if *debug_capture {
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
			atomic.AddInt64(&parent.factory.n_sessions, -1)
			if parent.in.reader != nil {
				parent.in.reader.ReassemblyComplete()
				parent.in.reader = nil
			}
			if parent.out.reader != nil {
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
func (p *TCPProtocol) Factory(port layers.TCPPort, inbound bool, config *string) tcpassembly.StreamFactory {
	factory := &tcpStreamFactory{
		port:          port,
		inbound:       inbound,
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
