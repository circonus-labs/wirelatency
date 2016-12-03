package wirelatency

import (
	"encoding/binary"
	"flag"
	"github.com/golang/snappy"
	"log"
	"strings"
	"time"
)

var debug_cql = flag.Bool("debug_cql", false, "Debug cassandra cql reassembly")

const (
	retainedPayloadSize int = 512

	cmd_ERROR        = uint8(0x00)
	cmd_STARTUP      = uint8(0x01)
	cmd_READY        = uint8(0x02)
	cmd_AUTHENTICATE = uint8(0x03)
	cmd_CREDENTIALS  = uint8(0x04)
	cmd_OPTIONS      = uint8(0x05)
	cmd_SUPPORTED    = uint8(0x06)
	cmd_QUERY        = uint8(0x07)
	cmd_RESULT       = uint8(0x08)
	cmd_PREPARE      = uint8(0x09)
	cmd_EXECUTE      = uint8(0x0A)
	cmd_REGISTER     = uint8(0x0B)
	cmd_EVENT        = uint8(0x0C)

	flag_COMPRESSION = uint8(0x01)
	flag_TRACING     = uint8(0x02)
)

type cassandra_cql_frame struct {
	complete               bool
	so_far                 int
	response               bool
	version, flags, opcode uint8
	stream                 int16
	length                 uint32
	length_bytes           [4]byte
	payload                []byte
	data                   []byte // the uncompressed frame payload
	truncated              bool   // don't use the payload, it's not all there

	//
	timestamp time.Time
}
type cassandra_cql_Parser struct {
	factory        *cassandra_cql_ParserFactory
	streams        map[int16][]cassandra_cql_frame
	request_frame  cassandra_cql_frame
	response_frame cassandra_cql_frame
}

func cassandra_cql_frame_OpcodeName(code uint8) string {
	switch code {
	case cmd_ERROR:
		return "Error"
	case cmd_STARTUP:
		return "Startup"
	case cmd_READY:
		return "Ready"
	case cmd_AUTHENTICATE:
		return "Authenticate"
	case cmd_CREDENTIALS:
		return "Credentials"
	case cmd_OPTIONS:
		return "Options"
	case cmd_SUPPORTED:
		return "Supported"
	case cmd_QUERY:
		return "Query"
	case cmd_RESULT:
		return "Result"
	case cmd_PREPARE:
		return "Prepare"
	case cmd_EXECUTE:
		return "Execute"
	case cmd_REGISTER:
		return "Register"
	case cmd_EVENT:
		return "Event"
	}
	return "unknown"
}
func (f *cassandra_cql_frame) OpcodeName() string {
	return cassandra_cql_frame_OpcodeName(f.opcode)
}
func (f *cassandra_cql_frame) init() {
	f.complete = false
	f.response = false
	f.so_far = 0
	f.version = 0
	f.flags = 0
	f.stream = 0
	f.opcode = 0
	f.length = 0
	f.data = nil
	f.truncated = false
	if f.payload == nil || cap(f.payload) != retainedPayloadSize {
		f.payload = make([]byte, retainedPayloadSize, retainedPayloadSize)
	}
	f.payload = f.payload[:0]
}

// Takes "more" data in and attempts to complete the frame
// returns complete if the frame is complete. Always returns
// the number of bytes of the passed data used.  used should
// be the entire data size if frame is incomplete
// If things go off the rails unrecoverably, used = -1 is returned
func (f *cassandra_cql_frame) fillFrame(seen time.Time, data []byte) (complete bool, used int) {
	if len(data) < 1 {
		return false, 0
	}
	if f.so_far == 0 {
		f.timestamp = seen
		f.version = data[used]
		f.response = (f.version&0x80 == 0x80)
		f.version = f.version & ^uint8(0x80)
		f.so_far = f.so_far + 1
		used = used + 1
	}
	headersize := 9
	if f.version > 2 {
		for ; used < len(data) && f.so_far < headersize; f.so_far, used = f.so_far+1, used+1 {
			switch f.so_far {
			case 0:
			case 1:
				f.flags = data[used]
			case 2:
				f.stream = int16(data[used]) << 8
			case 3:
				f.stream = f.stream | int16(data[used])
			case 4:
				f.opcode = data[used]
			case 5:
				f.length_bytes[0] = data[used]
			case 6:
				f.length_bytes[1] = data[used]
			case 7:
				f.length_bytes[2] = data[used]
			case 8:
				f.length_bytes[3] = data[used]
				f.length = binary.BigEndian.Uint32(f.length_bytes[:])
			}
		}
	} else {
		headersize = 8
		for ; used < len(data) && f.so_far < headersize; f.so_far, used = f.so_far+1, used+1 {
			switch f.so_far {
			case 0:
			case 1:
				f.flags = data[used]
			case 2:
				f.stream = int16(int8(data[used]))
			case 3:
				f.opcode = data[used]
			case 4:
				f.length_bytes[0] = data[used]
			case 5:
				f.length_bytes[1] = data[used]
			case 6:
				f.length_bytes[2] = data[used]
			case 7:
				f.length_bytes[3] = data[used]
				f.length = binary.BigEndian.Uint32(f.length_bytes[:])
			}
		}
	}
	if f.so_far < headersize {
		return false, used
	}
	remaining := f.length - uint32(f.so_far-headersize)
	to_append := remaining // how much we're actually reading
	if uint32(len(data)-used) < remaining {
		// not complete
		to_append = uint32(len(data) - used)
	}
	capped_append := to_append // how much we're actually writing
	if len(f.payload)+int(to_append) > cap(f.payload) {
		capped_append = uint32(cap(f.payload) - len(f.payload))
		f.truncated = true
	}
	if *debug_cql {
		log.Printf("[cql] need to read %d of %d, just %d capped to %d\n", remaining, f.length, to_append, capped_append)
	}
	if capped_append > 0 {
		f.payload = append(f.payload, data[used:(used+int(capped_append))]...)
	}
	used = used + int(to_append)
	f.so_far += int(to_append)
	if remaining == to_append {
		if 0 != (f.flags & flag_COMPRESSION) {
			if data, err := snappy.Decode(nil, f.payload); err == nil {
				f.data = data
			}
		} else {
			f.data = f.payload
		}
		f.complete = true
		return true, used
	}
	return false, used
}
func (p *cassandra_cql_Parser) pushOnStream(f *cassandra_cql_frame) {
	if fifo, ok := p.streams[f.stream]; ok {
		fifo = append(fifo, *f)
	} else {
		p.streams[f.stream] = make([]cassandra_cql_frame, 0, 5)
		p.streams[f.stream] = append(p.streams[f.stream], *f)
	}
}
func (p *cassandra_cql_Parser) popFromStream(stream int16) (f *cassandra_cql_frame) {
	f = nil
	if fifo, ok := p.streams[stream]; ok {
		if len(fifo) > 0 {
			f, fifo = &fifo[0], fifo[1:]
		}
	}
	return f
}

func read_longstring(data []byte) (out string, ok bool) {
	if len(data) < 4 {
		return "", false
	}
	strlen := binary.BigEndian.Uint32(data)
	if len(data) < (4 + int(strlen)) {
		return "", false
	}
	return string(data[4 : strlen+4]), true
}

var DEFAULT_CQL string = "unknown cql"

func (p *cassandra_cql_Parser) report(req, resp *cassandra_cql_frame) {
	var cql *string
	cql = &DEFAULT_CQL
	if req.opcode == cmd_QUERY && req.data != nil {
		if qcql, ok := read_longstring(req.data); ok {
			cql = &qcql
		}
	}
	if req.opcode == cmd_PREPARE && req.data != nil {
		if qcql, ok := read_longstring(req.data); ok {
			if resp.data != nil && len(resp.data) >= 2 {
				qcql = strings.Replace(qcql, "\n", " ", -1)
				qcql = strings.Replace(qcql, "\r", " ", -1)
				cql = &qcql
				p.factory.parsed[binary.BigEndian.Uint16(resp.data)] = *cql
			}
		}
	}
	if req.opcode == cmd_EXECUTE && req.data != nil && len(req.data) >= 2 {
		id := binary.BigEndian.Uint16(req.data)
		if prepared_cql, ok := p.factory.parsed[id]; ok {
			cql = &prepared_cql
		} else {
			cql = &DEFAULT_CQL
		}
	}

	duration := resp.timestamp.Sub(req.timestamp)

	name := req.OpcodeName()

	wl_track_int64("bytes", int64(req.length), name+"`request_bytes")
	wl_track_int64("bytes", int64(resp.length), name+"`response_bytes")
	wl_track_float64("seconds", float64(duration)/1000000000.0, name+"`latency")

	if req.opcode == cmd_EXECUTE {
		// track query-specific execute metrics, in addition to aggregate
		execName := name + "`" + *cql
		wl_track_int64("bytes", int64(req.length), execName+"`request_bytes")
		wl_track_int64("bytes", int64(resp.length), execName+"`response_bytes")
		wl_track_float64("seconds", float64(duration)/1000000000.0, execName+"`latency")
	}
}
func (p *cassandra_cql_Parser) InBytes(stream *tcpTwoWayStream, seen time.Time, data []byte) bool {
	// build a request
	for {
		if len(data) == 0 {
			if *debug_cql {
				log.Printf("[cql] incomplete in frame\n")
			}
			return true
		}
		if complete, used := p.request_frame.fillFrame(seen, data); complete {
			p.pushOnStream(&p.request_frame)
			data = data[used:]
			p.request_frame.init()
		} else if used < 0 {
			if *debug_cql {
				log.Printf("[cql] bad in frame\n")
			}
			return false
		} else if !complete {
			if *debug_cql {
				log.Printf("[cql] incomplete in frame\n")
			}
			return true
		}
	}
}
func (p *cassandra_cql_Parser) OutBytes(stream *tcpTwoWayStream, seen time.Time, data []byte) bool {
	for {
		if len(data) == 0 {
			if *debug_cql {
				log.Printf("[cql] incomplete out frame\n")
			}
			return true
		}
		if complete, used := p.response_frame.fillFrame(seen, data); complete {
			req := p.popFromStream(p.response_frame.stream)
			if *debug_cql {
				log.Printf("[cql] %p response %+v\n", req, &p.response_frame)
			}
			if req != nil {
				p.report(req, &p.response_frame)
			}
			data = data[used:]
			p.response_frame.init()
		} else if used < 0 {
			if *debug_cql {
				log.Printf("[cql] bad out frame\n")
			}
			return false
		} else if !complete {
			if *debug_cql {
				log.Printf("[cql] incomplete out frame\n")
			}
			return true
		}
	}
}
func (p *cassandra_cql_Parser) ManageIn(stream *tcpTwoWayStream) {
}
func (p *cassandra_cql_Parser) ManageOut(stream *tcpTwoWayStream) {
}

type cassandra_cql_ParserFactory struct {
	parsed map[uint16]string
}

func (f *cassandra_cql_ParserFactory) New() TCPProtocolInterpreter {
	p := cassandra_cql_Parser{}
	p.factory = f
	p.streams = make(map[int16][]cassandra_cql_frame)
	p.request_frame.init()
	p.response_frame.init()
	return &p
}
func init() {
	factory := &cassandra_cql_ParserFactory{}
	factory.parsed = make(map[uint16]string)
	cassProt := &TCPProtocol{name: "cassandra_cql", defaultPort: 9042}
	cassProt.interpFactory = factory
	RegisterTCPProtocol(cassProt)
}
