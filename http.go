package wirelatency

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
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

type httpParser struct {
	l             sync.Mutex
	reqs          []*http.Request
	current_start []time.Time
	req_sizes     []int
	last_in       time.Time
	ta_firstbyte  time.Time
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
	if len(p.current_start) > 0 && p.ta_firstbyte.Before(p.current_start[0]) {
		p.ta_firstbyte = seen
	} else if p.ta_firstbyte.Before(p.last_in) {
		p.ta_firstbyte = seen
	}
	return true
}
func (p *httpParser) ManageIn(stream *tcpTwoWayStream) {
	r_in := bufio.NewReader(stream.in.reader)
	for {
		var req *http.Request
		if newReq, err := http.ReadRequest(r_in); err == io.EOF {
			return
		} else if err != nil {
			if *debug_wl_http {
				log.Println("Error parsing HTTP requests:", err)
			}
		} else {
			req = newReq
			nbytes := tcpreader.DiscardBytesToEOF(req.Body)
			if *debug_wl_http {
				fmt.Println("Body contains", nbytes, "bytes")
			}
			p.l.Lock()
			start := p.last_in
			p.reqs = append(p.reqs, req)
			p.current_start = append(p.current_start, start)
			p.req_sizes = append(p.req_sizes, nbytes)
			p.l.Unlock()
		}
	}
}

func (p *httpParser) ManageOut(stream *tcpTwoWayStream) {
	var start time.Time
	var req_size int
	r_out := bufio.NewReader(stream.out.reader)
	for {
		var req *http.Request
		if resp, err := http.ReadResponse(r_out, req); err == io.EOF {
			return
		} else if err != nil {
			if *debug_wl_http {
				log.Println("Error parsing HTTP responses:", err)
			}
			return
		} else {
			p.l.Lock()
			start, p.current_start = p.current_start[0], p.current_start[1:]
			tt_firstbyte := p.ta_firstbyte.Sub(start)
			req_size, p.req_sizes = p.req_sizes[0], p.req_sizes[1:]
			req, p.reqs = p.reqs[0], p.reqs[1:]
			p.l.Unlock()

			nbytes := tcpreader.DiscardBytesToEOF(resp.Body)
			resp.Body.Close()
			if *debug_wl_http {
				fmt.Println("Body contains", nbytes, "bytes")
			}
			tt_duration := time.Now().Sub(start)
			name := UrlMatch((*stream.factory).config, req.URL.Path)
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
			name = req.Method + "`" + name + "`" + status_name
			wl_track_float64("seconds", float64(tt_firstbyte)/1000000000.0, name+"`firstbyte_latency")
			wl_track_float64("seconds", float64(tt_duration)/1000000000.0, name+"`latency")
			wl_track_int64("bytes", int64(req_size), name+"`request_bytes")
			wl_track_int64("bytes", int64(nbytes), name+"`response_bytes")
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
