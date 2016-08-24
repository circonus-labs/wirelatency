package wirelatency

import (
	"encoding/json"
	"flag"
	"github.com/postwait/gopacket/tcpassembly/tcpreader"
	"io"
	"io/ioutil"
	"log"
	"math"
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
	l        sync.Mutex
	reqinfo  []*httpReqInfo
	respinfo []*httpRespInfo
}

func (p *httpParser) InBytes(stream *tcpTwoWayStream, seen time.Time, data []byte) bool {
	return true
}
func (p *httpParser) OutBytes(stream *tcpTwoWayStream, seen time.Time, data []byte) bool {
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
		tt_firstbyte := math.Max(float64(resp.ta_firstbyte.Sub(req.start)), 0.00001)
		tt_duration := math.Max(float64(resp.end.Sub(req.start)), 0.00001)
		wl_track_float64("seconds", tt_firstbyte/1000000000.0, name+"`firstbyte_latency")
		wl_track_float64("seconds", tt_duration/1000000000.0, name+"`latency")
		wl_track_int64("bytes", int64(req.size), name+"`request_bytes")
		wl_track_int64("bytes", int64(resp.size), name+"`response_bytes")
	}
}
func (p *httpParser) ManageIn(stream *tcpTwoWayStream) {
	defer func() {
		if r := recover(); r != nil {
			if *debug_wl_http {
				log.Println("[RECOVERY] (http/ManageIn): %v", r)
			}
		}
	}()
	var config interface{}
	factory := stream.factory
	if factory != nil {
		config = factory.config
	}
	r_in := stream.in.reader
	for {
		var req *http.Request
		_, err := r_in.ReadByte()
		if err == nil {
			err = r_in.UnreadByte()
		}
		if err != nil {
			if *debug_wl_http {
				log.Println("[DEBUG] Error parsing HTTP requests:", err)
			}
			return
		}
		start_time := time.Now()

		if newReq, err := http.ReadRequest(r_in); err == io.EOF {
			return
		} else if err != nil {
			if *debug_wl_http {
				log.Println("[DEBUG] Error parsing HTTP requests:", err)
			}
			return
		} else {
			if *debug_wl_http {
				log.Println("[DEBUG] new request read.")
			}
			req = newReq
			nbytes, derr := tcpreader.DiscardBytesToFirstError(req.Body)
			if derr != nil && derr != io.EOF {
				if *debug_wl_http {
					log.Println("[DEBUG] error reading request body: %v", derr)
				}
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
				start:  start_time,
				size:   nbytes,
			})
			p.l.Unlock()
			p.process()
		}
	}
}

func (p *httpParser) ManageOut(stream *tcpTwoWayStream) {
	defer func() {
		if r := recover(); r != nil {
			if *debug_wl_http {
				log.Println("[RECOVERY] (http/ManageOut): %v", r)
			}
		}
	}()
	r_out := stream.out.reader
	for {
		var req *http.Request
		_, err := r_out.ReadByte()
		if err == nil {
			err = r_out.UnreadByte()
		}
		if err != nil {
			if *debug_wl_http {
				log.Println("[DEBUG] Error parsing HTTP requests:", err)
			}
			return
		}
		ta_firstbyte := time.Now()

		if resp, err := http.ReadResponse(r_out, req); err == io.EOF {
			return
		} else if err != nil {
			if *debug_wl_http {
				log.Println("[DEBUG] Error parsing HTTP responses:", err)
				log.Printf("[%+v]\n", stream.out)
			}
			return
		} else {
			if *debug_wl_http {
				log.Println("[DEBUG] new response read.")
			}
			nbytes, derr := tcpreader.DiscardBytesToFirstError(resp.Body)
			if derr != nil && derr != io.EOF {
				if *debug_wl_http {
					log.Println("[DEBUG] error reading http response body: %v", derr)
				}
				return
			}
			ta_lastbyte := time.Now()
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
