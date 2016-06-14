package wirelatency

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
	"log"
	"strconv"
	"sync"
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
	cleanup       chan *tcpTwoWayStream
}

const (
	sessionStateBlank = iota
	sessionStateGood  = iota
	sessionStateBad   = iota
)

type tcpTwoWayStream struct {
	factory          *tcpStreamFactory
	interp           *TCPProtocolInterpreter
	in, out          *tcpStream
	state            int
	cleanupCondition chan string
}

type tcpStream struct {
	inbound                             bool
	net, transport                      gopacket.Flow
	bytes, packets, outOfOrder, skipped int64
	start, end                          time.Time
	sawStart, sawEnd                    bool
	reader_mu                           sync.Mutex
	readerDone                          bool
	reader                              *tcpreader.ReaderStream
	parent                              *tcpTwoWayStream
}
type noopTcpStream struct {
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
func (factory *tcpStreamFactory) doCleanup() {
	for {
		tofree := <-factory.cleanup
		go func(twa *tcpTwoWayStream) {
			if *debug_capture {
				log.Printf("[DEBUG] cleaning up %v", twa)
			}
			for i := 0; i < 2; i++ {
				part := <-twa.cleanupCondition // the in side
				if *debug_capture {
					log.Printf("[DEBUG] %v cleaned up %v", twa, part)
				}
			}
			close(twa.cleanupCondition)
			if twa.in != nil {
				twa.in.parent = nil
				twa.in.reader = nil
			}
			twa.in = nil
			if twa.out != nil {
				twa.out.parent = nil
				twa.out.reader = nil
			}
			twa.out = nil
			twa.factory = nil
			twa.interp = nil
		}(tofree)
	}
}
func (factory *tcpStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	inbound := transport.Dst().String() == strconv.Itoa(int(factory.port)) && isLocalDst(net.Dst())
	if !inbound {
		if !(transport.Src().String() == strconv.Itoa(int(factory.port)) && isLocalDst(net.Src())) {
			if *debug_capture {
				log.Printf("[DEBUG] discarding %v:%v", net, transport)
			}
			return &noopTcpStream{}
		}
	}
	net_session := net
	transport_session := transport
	if !inbound {
		net_session = net.Reverse()
		transport_session = transport.Reverse()
	}

	if *debug_capture {
		log.Printf("[DEBUG] New(%v, %v)\n", net, transport)
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
		parent.cleanupCondition = make(chan string, 2)
		dsess[transport_session] = parent
	}

	// We can't very will have new streams where we have old streams.
	if inbound && parent.in != nil {
		return &noopTcpStream{}
	}
	if !inbound && parent.out != nil {
		return &noopTcpStream{}
	}

	// Handle the inbound initial session startup
	interp := *parent.interp
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
				interp.ManageIn(parent)
				if *debug_capture {
					log.Printf("[DEBUG] go ManageIn(%v:%v) ended", s.net, s.transport)
				}
				parent.cleanupCondition <- "in async"
			}()
		} else {
			s.readerDone = true
			parent.cleanupCondition <- "in immediate"
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
			interp.ManageOut(parent)
			if *debug_capture {
				log.Printf("[DEBUG] go ManageOut(%v:%v) ended", s.net, s.transport)
			}
			parent.cleanupCondition <- "out async"
		}()
	} else {
		s.readerDone = true
		parent.cleanupCondition <- "out immediate"
	}
	return s
}

func (s *noopTcpStream) Reassembled(reassemblies []tcpassembly.Reassembly) {
}
func (s *noopTcpStream) ReassemblyComplete() {
}

func (s *tcpStream) Reassembled(reassemblies []tcpassembly.Reassembly) {
	if s.parent == nil || s.parent.state == sessionStateBad {
		if *debug_capture {
			log.Printf("[DEBUG] %v:%v in bad state", s.net, s.transport)
		}
		s.reader_mu.Lock()
		if s.reader != nil && !s.readerDone {
			s.readerDone = true
			s.reader.ReassemblyComplete()
		}
		s.reader_mu.Unlock()
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

	s.reader_mu.Lock()
	if s.reader != nil && !s.readerDone {
		s.reader.Reassembled(reassemblies)
	}
	s.reader_mu.Unlock()
}
func (s *tcpStream) ReassemblyComplete() {
	net_session := s.net
	transport_session := s.transport
	if !s.inbound {
		net_session = s.net.Reverse()
		transport_session = s.transport.Reverse()
	}

	if reader := s.reader; reader != nil {
		if *debug_capture {
			log.Printf("[DEBUG] reassembly complete (inbound: %v): %v:%v", s.inbound, s.net, s.transport)
		}
		s.reader_mu.Lock()
		if !s.readerDone {
			s.readerDone = true
			reader.ReassemblyComplete()
		}
		s.reader_mu.Unlock()
	}
	if dsess, ok := sessions[net_session]; ok {
		if parent, ok := dsess[transport_session]; ok {
			factory := parent.factory
			if s == parent.in {
				atomic.AddInt64(&factory.n_sessions, -1)
			}
			if *debug_capture {
				log.Printf("[DEBUG] reassembly done %v:%v", s.net, s.transport)
				log.Printf("[DEBUG] removing sub session: %v:%v", s.net, s.transport)
			}
			delete(dsess, transport_session)
			factory.cleanup <- parent
		}
		if len(dsess) == 0 {
			if *debug_capture {
				log.Printf("[DEBUG] removing session: %v", s.net)
			}
			delete(sessions, net_session)
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
		cleanup:       make(chan *tcpTwoWayStream, 10),
	}
	if metrics != nil {
		base := p.Name() + "`" + port.String()
		metrics.SetCounterFunc(base+"`total_sessions",
			func() uint64 { return uint64(factory.n_clients) })
		metrics.SetGaugeFunc(base+"`active_sessions",
			func() int64 { return factory.n_sessions })
	}
	go factory.doCleanup()
	return factory
}
