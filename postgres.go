package wirelatency

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var debug_postgres = flag.Bool("debug_postgres", false, "Debug postgres reassembly")

var pg_sql_wsp *regexp.Regexp
var pg_dealloc_re *regexp.Regexp

type queryMap struct {
	query_re *regexp.Regexp
	Query    string
	Name     string
}
type postgresConfig struct {
	AdhocStatements    []queryMap
	PreparedStatements []queryMap
}

func postgresConfigParser(c *string) interface{} {
	var config postgresConfig
	config = postgresConfig{
		PreparedStatements: make([]queryMap, 0),
		AdhocStatements:    make([]queryMap, 0),
	}
	if c == nil {
		var default_endpoints = make([]queryMap, 1)
		default_endpoints[0] = queryMap{
			Query: ".",
			Name:  "",
		}
		config.PreparedStatements = default_endpoints
	} else {
		file, e := ioutil.ReadFile(*c)
		if e != nil {
			panic(e)
		}
		err := json.Unmarshal(file, &config)
		if err != nil {
			panic(err)
		}
	}
	for i := 0; i < len(config.AdhocStatements); i++ {
		config.AdhocStatements[i].query_re = regexp.MustCompile(config.AdhocStatements[i].Query)
	}
	for i := 0; i < len(config.PreparedStatements); i++ {
		config.PreparedStatements[i].query_re = regexp.MustCompile(config.PreparedStatements[i].Query)
	}

	return config
}

func init() {
	pg_sql_wsp = regexp.MustCompile("[\\r\\n\\s]+")
	pg_dealloc_re = regexp.MustCompile("(?i)^\\s*DEALLOCATE\\s+(\\S+)")
}

const (
	pg_retainedPayloadSize int = 1024
	// we make these up, the don't have codes
	pg_Startup_F    = uint8(0)
	pg_SSLRequest_F = uint8(1)

	// frontend
	pg_Bind_F            = uint8('B')
	pg_Close_F           = uint8('C')
	pg_CopyData_F        = uint8('d')
	pg_CopyDone_F        = uint8('c')
	pg_CopyFail_F        = uint8('f')
	pg_Describe_F        = uint8('D')
	pg_Execute_F         = uint8('E')
	pg_Flush_F           = uint8('H')
	pg_FunctionCall_F    = uint8('F')
	pg_Parse_F           = uint8('P')
	pg_PasswordMessage_F = uint8('p')
	pg_Query_F           = uint8('Q')
	pg_Sync_F            = uint8('S')
	pg_Terminate_F       = uint8('X')

	// backend
	pg_AuthenticationRequest_B = uint8('R')
	pg_BackendKeyData_B        = uint8('K')
	pg_BindComplete_B          = uint8('2')
	pg_CloseComplete_B         = uint8('3')
	pg_CommandComplete_B       = uint8('C')
	pg_CopyData_B              = uint8('d')
	pg_CopyDone_B              = uint8('c')
	pg_CopyFail_B              = uint8('f')
	pg_CopyInResponse_B        = uint8('G')
	pg_CopyOutResponse_B       = uint8('H')
	pg_CopyBothResponse_B      = uint8('W')
	pg_DataRow_B               = uint8('D')
	pg_EmptyQueryResponse_B    = uint8('I')
	pg_ErrorResponse_B         = uint8('E')
	pg_FunctionCallResponse_B  = uint8('V')
	pg_NoData_B                = uint8('n')
	pg_NoticeResponse_B        = uint8('N')
	pg_NotificationResponse_B  = uint8('A')
	pg_ParameterDescription_B  = uint8('t')
	pg_ParameterStatus_B       = uint8('S')
	pg_ParseComplete_B         = uint8('1')
	pg_PortalSuspended_B       = uint8('s')
	pg_ReadyForQuery_B         = uint8('Z')
	pg_RowDescription_B        = uint8('T')
)

type postgres_frame struct {
	inbound      bool
	first        bool
	complete     bool
	so_far       int
	command      uint8
	length       uint32
	length_bytes [4]byte
	payload      []byte
	truncated    bool // don't use the payload, it's not all there

	//
	timestamp      time.Time
	should_log     bool
	longname       string
	response_bytes int
	response_rows  int
}
type postgres_Parser struct {
	factory          *postgres_ParserFactory
	stream           []postgres_frame
	request_frame    postgres_frame
	response_frame   postgres_frame
	prepared_queries map[string]string
	portals          map[string]string
}

func postgres_frame_CommandName_B(code uint8) (string, bool) {
	switch code {
	case pg_AuthenticationRequest_B:
		return "AuthenticationRequest", true
	case pg_BackendKeyData_B:
		return "BackendKeyData", true
	case pg_BindComplete_B:
		return "BindComplete", true
	case pg_CloseComplete_B:
		return "CloseComplete", true
	case pg_CommandComplete_B:
		return "CommandComplete", true
	case pg_CopyData_B:
		return "CopyData", true
	case pg_CopyDone_B:
		return "CopyDone", true
	case pg_CopyFail_B:
		return "CopyFail", true
	case pg_CopyInResponse_B:
		return "CopyInResponse", true
	case pg_CopyOutResponse_B:
		return "CopyOutResponse", true
	case pg_CopyBothResponse_B:
		return "CopyBothResponse", true
	case pg_DataRow_B:
		return "DataRow", true
	case pg_EmptyQueryResponse_B:
		return "EmptyQueryResponse", true
	case pg_ErrorResponse_B:
		return "ErrorResponse", true
	case pg_FunctionCallResponse_B:
		return "FunctionCallResponse", true
	case pg_NoData_B:
		return "NoData", true
	case pg_NoticeResponse_B:
		return "NoticeResponse", true
	case pg_NotificationResponse_B:
		return "NotificationResponse", true
	case pg_ParameterDescription_B:
		return "ParameterDescription", true
	case pg_ParameterStatus_B:
		return "ParameterStatus", true
	case pg_ParseComplete_B:
		return "ParseComplete", true
	case pg_PortalSuspended_B:
		return "PortalSuspended", true
	case pg_ReadyForQuery_B:
		return "ReadyForQuery", true
	case pg_RowDescription_B:
		return "RowDescription", true
	}
	return fmt.Sprintf("unknown:%d", code), false
}
func postgres_frame_CommandName_F(code uint8) (string, bool) {
	switch code {
	case pg_Startup_F:
		return "Startup", true
	case pg_SSLRequest_F:
		return "SSLRequest", true
	case pg_Bind_F:
		return "Bind", true
	case pg_Close_F:
		return "Close", true
	case pg_CopyData_F:
		return "CopyData", true
	case pg_CopyDone_F:
		return "CopyDone", true
	case pg_CopyFail_F:
		return "CopyFail", true
	case pg_Describe_F:
		return "Describe", true
	case pg_Execute_F:
		return "Execute", true
	case pg_Flush_F:
		return "Flush", true
	case pg_FunctionCall_F:
		return "FunctionCall", true
	case pg_Parse_F:
		return "Parse", true
	case pg_PasswordMessage_F:
		return "PasswordMessage", true
	case pg_Query_F:
		return "Query", true
	case pg_Sync_F:
		return "Sync", true
	case pg_Terminate_F:
		return "Terminate", true
	}
	return fmt.Sprintf("unknown: %c", code), false
}
func (f *postgres_frame) CommandName() string {
	if f.inbound {
		name, _ := postgres_frame_CommandName_F(f.command)
		return name
	}
	name, _ := postgres_frame_CommandName_B(f.command)
	return name
}
func (f *postgres_frame) copy() *postgres_frame {
	f_copy := *f
	// someone is going to squat on the payload, it's not ours anymore
	f_copy.payload = nil
	return &f_copy
}
func (f *postgres_frame) validateIn() bool {
	_, valid := postgres_frame_CommandName_F(f.command)
	return valid
}
func (f *postgres_frame) validateOut() bool {
	_, valid := postgres_frame_CommandName_B(f.command)
	return valid
}
func (f *postgres_frame) init() {
	f.first = false
	f.complete = false
	f.so_far = 0
	f.command = 0
	f.length = 0
	f.truncated = false
	f.response_rows = 0
	f.response_bytes = 0
	f.should_log = false
	f.longname = ""
	if f.payload == nil || cap(f.payload) != pg_retainedPayloadSize {
		f.payload = make([]byte, 0, pg_retainedPayloadSize)
	}
	f.payload = f.payload[:0]
}

// Takes "more" data in and attempts to complete the frame
// returns complete if the frame is complete. Always returns
// the number of bytes of the passed data used.  used should
// be the entire data size if frame is incomplete
// If things go off the rails unrecoverably, used = -1 is returned
func (f *postgres_frame) fillFrame(seen time.Time, data []byte) (complete bool, used int) {
	if len(data) < 1 {
		return false, 0
	}
	if f.so_far == 0 {
		f.timestamp = seen
		if f.inbound && data[used] != 0 {
			// We might be thinking about a first frame, but that's not going
			// to happen if the first byte is 0, we must be mid stream.
			f.first = false
		}
		if f.first {
			// The first packet is disgusting... it could be
			// a Startup or SSLRequest on the F side
			// or a single character response with no length on the B side
			if *debug_postgres {
				log.Printf("[DEBUG] expecting startup frame")
			}
			if f.inbound {
				f.command = pg_Startup_F
			} else {
				f.command = data[used]
				used = used + 1
				if f.command == uint8('N') {
					f.complete = true
					return true, used
				}
				if f.command == uint8('S') {
					f.complete = true
					return true, used
				}
			}
		} else {
			// Normal packes are sensible, first byte is command
			f.command = data[used]
			used = used + 1
		}
		f.so_far = f.so_far + 1
	}
	// Next four bytes are the length (inclusive of the four bytes?!)
	for ; used < len(data) && f.so_far < 5; f.so_far, used = f.so_far+1, used+1 {
		switch f.so_far {
		case 1:
			f.length_bytes[0] = data[used]
		case 2:
			f.length_bytes[1] = data[used]
		case 3:
			f.length_bytes[2] = data[used]
		case 4:
			f.length_bytes[3] = data[used]
			f.length = binary.BigEndian.Uint32(f.length_bytes[:])
		}
	}
	if f.so_far < 5 {
		return false, used
	}

	// Now we read in the legnth
	remaining := f.length - uint32(f.so_far-1)
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
	if capped_append > 0 {
		f.payload = append(f.payload, data[used:(used+int(capped_append))]...)
	}
	used = used + int(to_append)
	f.so_far = f.so_far + int(to_append)
	if remaining == to_append {
		f.complete = true
		if f.inbound && f.first && f.command == pg_Startup_F {
			// our startup message could be an SSLRequest
			if len(f.payload) == 4 && binary.BigEndian.Uint32(f.payload[:]) == 80877103 {
				// alter this post-facto to an SSLRequest so we can expect the
				// non-compliant response packet
				f.command = pg_SSLRequest_F
			}
		}
		if *debug_postgres {
			log.Printf("[DEBUG] frame completed")
		}
		return true, used
	}
	if *debug_postgres {
		log.Printf("[DEBUG] frame pending")
	}
	return false, used
}
func (p *postgres_Parser) pushStream(f *postgres_frame) {
	p.stream = append(p.stream, *f)
}
func (p *postgres_Parser) popStream() (f *postgres_frame) {
	f = nil
	if len(p.stream) > 0 {
		f, p.stream = &p.stream[0], p.stream[1:]
	}
	return f
}
func (p *postgres_Parser) peekStream() (f *postgres_frame) {
	if len(p.stream) > 0 {
		return &p.stream[0]
	}
	return nil
}
func (p *postgres_Parser) flushStream() {
	p.stream = make([]postgres_frame, 0, 2)
}

func pg_read_string(data []byte) (string, int) {
	for i, c := range data {
		if c == 0 {
			return string(data[0:i]), i
		}
	}
	return "", -1
}
func (p *postgres_Parser) bind(req, resp *postgres_frame) {
	if req.command != pg_Bind_F {
		if *debug_postgres {
			log.Printf("[DEBUG] out-of-order %v->%v", req.CommandName(), resp.CommandName())
		}
	}
	var name string
	portal, plen := pg_read_string(req.payload)
	if plen < 0 {
		return
	}
	name, nlen := pg_read_string(req.payload[plen+1:])
	if nlen < 0 {
		return
	}
	p.portals[portal] = name
}
func (p *postgres_Parser) store(req, resp *postgres_frame) {
	if req.command != pg_Parse_F {
		if *debug_postgres {
			log.Printf("[DEBUG] out-of-order %v->%v", req.CommandName(), resp.CommandName())
		}
	}
	var name string
	name, len := pg_read_string(req.payload)
	if len >= 0 {
		query, qlen := pg_read_string(req.payload[len+1:])
		if qlen >= 0 {
			p.prepared_queries[name] =
				strings.TrimSpace(pg_sql_wsp.ReplaceAllLiteralString(query, " "))
			if *debug_postgres {
				log.Printf("PARSED[%v] %v", name, p.prepared_queries[name])
			}
		}
	}
}
func (p *postgres_Parser) extract(config postgresConfig, req *postgres_frame) {
	req.should_log = true
	switch req.command {
	case pg_Parse_F:
		req.should_log = false
	case pg_Execute_F:
		if pname, len := pg_read_string(req.payload); len >= 0 {
			if portal, ok := p.portals[pname]; ok {
				if query, ok := p.prepared_queries[portal]; ok {
					for _, qm := range config.PreparedStatements {
						if qm.query_re.MatchString(query) {
							if qm.Name == "RAW" {
								req.longname = "Execute`" + query
							} else if qm.Name == "SHA256" {
								bsum := sha256.Sum256([]byte(query))
								csum := hex.EncodeToString(bsum[:])
								req.longname = "Execute`" + csum
							} else if qm.Name != "" {
								req.longname = "Execute`" + qm.Name
							}
							break
						}
					}
				}
			}
		}
	case pg_Query_F:
		if pname, len := pg_read_string(req.payload); len >= 0 {
			if *debug_postgres {
				log.Printf("QUERY[%v]", pname)
			}
			if m := pg_dealloc_re.FindStringSubmatch(pname); m != nil {
				if *debug_postgres {
					log.Printf("UNPARSE[%v]", m[1])
				}
				delete(p.prepared_queries, m[1])
				req.should_log = false
			} else {
				for _, qm := range config.AdhocStatements {
					if qm.query_re.MatchString(pname) {
						if qm.Name == "RAW" {
							req.longname = "Query`" + pname
						} else if qm.Name == "SHA256" {
							bsum := sha256.Sum256([]byte(pname))
							csum := hex.EncodeToString(bsum[:])
							req.longname = "Query`" + csum
						} else if qm.Name != "" {
							req.longname = "Query`" + qm.Name
						}
						break
					}
				}
			}
		}
	}
}
func (p *postgres_Parser) report(config postgresConfig, req, resp *postgres_frame) {
	should_log := req.should_log
	name := req.CommandName()
	duration := resp.timestamp.Sub(req.timestamp)
	types := make([]string, 1, 5)
	types[0] = ""
	result := ""
	if resp.command == pg_CommandComplete_B {
		var len int
		if result, len = pg_read_string(resp.payload); len >= 0 {
			if *debug_postgres {
				log.Printf("[COMPLETE] %v", result)
			}
		}
	}
	if rfields := strings.Fields(result); rfields != nil && len(rfields) > 1 {
		types = append(types, "`"+rfields[0])
		if nrows, err := strconv.ParseInt(rfields[len(rfields)-1], 10, 32); err == nil {
			req.response_rows = int(nrows)
		}
	}
	if should_log {
		for _, typename := range types {
			wl_track_int64("bytes", int64(req.length), name+typename+"`request_bytes")
			wl_track_int64("bytes", int64(req.response_bytes), name+typename+"`response_bytes")
			wl_track_int64("tuples", int64(req.response_rows), name+typename+"`response_rows")
			wl_track_float64("seconds", float64(duration)/1000000000.0, name+typename+"`latency")
		}
		if req.longname != "" {
			wl_track_int64("bytes", int64(req.length), req.longname+"`request_bytes")
			wl_track_int64("bytes", int64(req.response_bytes), req.longname+"`response_bytes")
			wl_track_int64("tuples", int64(req.response_rows), req.longname+"`response_rows")
			wl_track_float64("seconds", float64(duration)/1000000000.0, req.longname+"`latency")
		}
	}
}
func (p *postgres_Parser) reset() {
	p.stream = make([]postgres_frame, 1)
	p.request_frame.init()
	p.request_frame.inbound = true
	p.response_frame.init()
}
func (p *postgres_Parser) InBytes(stream *tcpTwoWayStream, seen time.Time, data []byte) bool {
	// build a request
	for {
		if len(data) == 0 {
			return true
		}
		if complete, used := p.request_frame.fillFrame(seen, data); complete {
			if p.request_frame.first && p.request_frame.command <= pg_SSLRequest_F {
				p.response_frame.first = (p.request_frame.command == pg_SSLRequest_F)
				p.request_frame.init()
				data = data[used:]
				continue
			}
			if !p.request_frame.validateIn() {
				if *debug_postgres {
					log.Printf("<- BAD FRAME: %v", p.request_frame.CommandName())
				}
				p.reset()
				return true
			}
			switch p.request_frame.command {
			case pg_Bind_F:
				fallthrough
			case pg_Query_F:
				fallthrough
			case pg_Execute_F:
				fallthrough
			case pg_Parse_F:
				if *debug_postgres {
					log.Printf("<- %v queued", p.request_frame.CommandName())
				}
				p.extract(stream.factory.config.(postgresConfig), &p.request_frame)
				p.pushStream(p.request_frame.copy())
			default:
				if *debug_postgres {
					log.Printf("<- %v discard", p.request_frame.CommandName())
				}
			}
			data = data[used:]
			p.request_frame.init()
		} else if used < 0 {
			if *debug_postgres {
				log.Printf("<- BAD READ IN: %v", used)
			}
			p.reset()
			return true
		} else if !complete {
			return true
		}
	}
}
func (p *postgres_Parser) OutBytes(stream *tcpTwoWayStream, seen time.Time, data []byte) bool {
	var pgConfig postgresConfig
	if stream == nil || stream.factory == nil || stream.factory.config == nil {
		return false
	}
	pgConfig = stream.factory.config.(postgresConfig)
	for {
		if len(data) == 0 {
			return true
		}
		if complete, used := p.response_frame.fillFrame(seen, data); complete {
			if p.response_frame.first {
				if p.response_frame.command != uint8('N') {
					if *debug_postgres {
						log.Printf("[DEBUG] abandoning SSL session")
					}
					return false
				}
				if *debug_capture {
					log.Printf("[DEBUG] SSLRequest denied, normal startup")
				}
				data = data[used:]
				p.response_frame.init()
				p.request_frame.first = true
				continue
			}
			if !p.response_frame.validateOut() {
				if *debug_postgres {
					log.Printf("-> BAD FRAME: %v", p.request_frame.CommandName())
				}
				p.reset()
				return true
			}
			req := p.peekStream()
			if req != nil {
				req.response_bytes += p.response_frame.so_far
			}

			if *debug_postgres {
				log.Printf("-> %v", p.response_frame.CommandName())
			}
			if p.response_frame.command == pg_ReadyForQuery_B {
				p.flushStream()
				req = nil
			}
			if req != nil {
				switch p.response_frame.command {
				case pg_DataRow_B:
					req.response_rows++
				case pg_BindComplete_B:
					p.bind(p.popStream(), &p.response_frame)
				case pg_ParseComplete_B:
					p.store(p.popStream(), &p.response_frame)
				case pg_CommandComplete_B:
					p.report(pgConfig, p.popStream(), &p.response_frame)
				}
			}

			data = data[used:]
			p.response_frame.init()
		} else if used < 0 {
			if *debug_postgres {
				log.Printf("-> BAD READ OUT: %v", used)
			}
			p.reset()
			return true
		} else if !complete {
			return true
		}
	}
}
func (p *postgres_Parser) ManageIn(stream *tcpTwoWayStream) {
	panic("postgres wirelatency parser is not async")
}
func (p *postgres_Parser) ManageOut(stream *tcpTwoWayStream) {
	panic("postgres wirelatency parser is not async")
}

type postgres_ParserFactory struct {
	parsed map[uint16]string
}

func (f *postgres_ParserFactory) New() TCPProtocolInterpreter {
	p := postgres_Parser{}
	p.factory = f
	p.prepared_queries = make(map[string]string)
	p.portals = make(map[string]string)
	p.reset()
	p.request_frame.first = true
	return &p
}
func init() {
	factory := &postgres_ParserFactory{}
	postgresProt := &TCPProtocol{
		name:        "postgres",
		defaultPort: 5432,
		inFlight:    true,
		Config:      postgresConfigParser,
	}
	postgresProt.interpFactory = factory
	RegisterTCPProtocol(postgresProt)
}
