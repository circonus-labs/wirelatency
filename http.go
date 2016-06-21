package wirelatency

import (
	"bufio"
	"encoding/json"
	"flag"
	"github.com/google/gopacket/tcpassembly/tcpreader"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"regexp"
	"sync"
	"time"
)

var debug_wl_http = flag.Bool("debug_wl_http", false, "Debug wirelatency HTTP decoding")

type httpEndpointMap struct {
	path_re *regexp.Regexp
	Path    string
	Name    string
}
type httpConfig struct {
	Routes []httpEndpointMap
}

type httpReqInfo struct {
	name   string
	method string
	start  time.Time
	size   int
}
type httpRespInfo struct {
	status_name  string
	size         int
	ta_firstbyte time.Time
	end          time.Time
}
type httpParser struct {
	l            sync.Mutex
	reqinfo      []*httpReqInfo
	respinfo     []*httpRespInfo
	last_in      time.Time
	ta_firstbyte time.Time
	ta_lastbyte  time.Time
}

func (p *httpParser) InBytes(seen time.Time, data []byte) bool {
	p.last_in = seen
	return true
}
func (p *httpParser) OutBytes(seen time.Time, data []byte) bool {
	if len(data) < 0 {
		return true
	}
	p.l.Lock()
	defer p.l.Unlock()
	p.ta_lastbyte = seen
	if p.ta_firstbyte.Before(p.last_in) {
		p.ta_firstbyte = seen
	}
	return true
}
func (p *httpParser) process() {
	p.l.Lock()
	defer p.l.Unlock()
	for len(p.reqinfo) > 0 && len(p.respinfo) > 0 {
		var req *httpReqInfo
		var resp *httpRespInfo
		req, p.reqinfo = p.reqinfo[0], p.reqinfo[1:]
		resp, p.respinfo = p.respinfo[0], p.respinfo[1:]
		name := req.method + "`" + req.name + "`" + resp.status_name
		tt_firstbyte := resp.ta_firstbyte.Sub(req.start)
		tt_duration := resp.end.Sub(req.start)
		wl_track_float64("seconds", float64(tt_firstbyte)/1000000000.0, name+"`firstbyte_latency")
		wl_track_float64("seconds", float64(tt_duration)/1000000000.0, name+"`latency")
		wl_track_int64("bytes", int64(req.size), name+"`request_bytes")
		wl_track_int64("bytes", int64(resp.size), name+"`response_bytes")
	}
}
func (p *httpParser) ManageIn(stream *tcpTwoWayStream) {
	var config interface{}
	factory := stream.factory
	if factory != nil {
		config = factory.config
	}
	r_in := bufio.NewReader(stream.in.reader)
	for {
		var req *http.Request
		if newReq, err := http.ReadRequest(r_in); err == io.EOF {
			return
		} else if err != nil {
			if *debug_wl_http {
				log.Println("[DEBUG] Error parsing HTTP requests:", err)
			}
		} else {
			req = newReq
			nbytes, derr := tcpreader.DiscardBytesToFirstError(req.Body)
			if derr != nil && derr != io.EOF {
				log.Println("[ERROR] error reading request body: %v", derr)
				return
			}
			if *debug_wl_http {
				log.Println("[DEBUG] Body contains", nbytes, "bytes")
			}
			path := "unknown"
			if req.URL != nil {
				path = req.URL.Path
			}
			p.l.Lock()
			p.reqinfo = append(p.reqinfo, &httpReqInfo{
				name:   UrlMatch(config, path),
				method: req.Method,
				start:  p.last_in,
				size:   nbytes,
			})
			p.l.Unlock()
			p.process()
		}
	}
}

func (p *httpParser) ManageOut(stream *tcpTwoWayStream) {
	r_out := bufio.NewReader(stream.out.reader)
	for {
		var req *http.Request
		if resp, err := http.ReadResponse(r_out, req); err == io.EOF {
			return
		} else if err != nil {
			if *debug_wl_http {
				log.Println("[DEBUG] Error parsing HTTP responses:", err)
			}
			return
		} else {
			p.l.Lock()
			ta_firstbyte := p.ta_firstbyte
			p.l.Unlock()
			nbytes, derr := tcpreader.DiscardBytesToFirstError(resp.Body)
			if derr != nil && derr != io.EOF {
				log.Println("[ERROR] error reading http response body: %v", derr)
				return
			}
			p.l.Lock()
			ta_lastbyte := p.ta_lastbyte
			p.l.Unlock()
			resp.Body.Close()
			if *debug_wl_http {
				log.Println("[DEBUG] Body contains", nbytes, "bytes")
			}
			status_name := "xxx"
			switch {
			case resp.StatusCode >= 0 && resp.StatusCode < 100:
				status_name = "0xx"
			case resp.StatusCode >= 100 && resp.StatusCode < 200:
				status_name = "1xx"
			case resp.StatusCode >= 200 && resp.StatusCode < 300:
				status_name = "2xx"
			case resp.StatusCode >= 300 && resp.StatusCode < 400:
				status_name = "3xx"
			case resp.StatusCode >= 400 && resp.StatusCode < 500:
				status_name = "4xx"
			case resp.StatusCode >= 500 && resp.StatusCode < 600:
				status_name = "5xx"
			}
			p.l.Lock()
			p.respinfo = append(p.respinfo, &httpRespInfo{
				status_name:  status_name,
				size:         nbytes,
				ta_firstbyte: ta_firstbyte,
				end:          ta_lastbyte,
			})
			p.l.Unlock()

			p.process()
		}
	}
}

func UrlMatch(iconfig interface{}, url string) string {
	config := iconfig.(httpConfig)
	for _, route := range config.Routes {
		if route.path_re.MatchString(url) {
			return route.Name
		}
	}
	return "unmatched_route"
}

type httpParserFactory struct{}

func (f httpParserFactory) New() TCPProtocolInterpreter {
	p := httpParser{}
	return &p
}
func httpConfigParser(c *string) interface{} {
	var config httpConfig
	config = httpConfig{Routes: make([]httpEndpointMap, 0)}
	if c == nil {
		var default_endpoints = make([]httpEndpointMap, 1)
		default_endpoints[0] = httpEndpointMap{
			Path: "^/",
			Name: "default",
		}
		config.Routes = default_endpoints
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
	for i := 0; i < len(config.Routes); i++ {
		config.Routes[i].path_re = regexp.MustCompile(config.Routes[i].Path)
	}

	return config
}
func init() {
	factory := &httpParserFactory{}
	httpProt := &TCPProtocol{
		name:        "http",
		useReaders:  true,
		defaultPort: 80,
		Config:      httpConfigParser,
	}
	httpProt.interpFactory = factory
	RegisterTCPProtocol(httpProt)
}
