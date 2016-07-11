package main

import (
	"errors"
	"flag"
	"fmt"
	"github.com/circonus-labs/circonus-gometrics"
	"github.com/circonus-labs/wirelatency"
	"github.com/google/gopacket/layers"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"strconv"
	"strings"
)

var version string = "0.0.3"

type localip struct{}

func (r *localip) String() string {
	return "complex multiple values"
}

func (r *localip) Set(value string) error {
	ip := net.ParseIP(value)
	if ip == nil {
		return errors.New(fmt.Sprintf("Invalid IP address: %s\n", value))
	}
	wirelatency.AddLocalIP(ip)
	return nil
}

type regflag struct{}

func (r *regflag) String() string {
	return "complex multiple values"
}

type wiring struct {
	proto  string
	port   layers.TCPPort
	config *string
}

var wirings []wiring = make([]wiring, 0, 1)

func (r *regflag) Set(value string) error {
	parts := strings.SplitN(value, ":", 3)
	proto := parts[0]
	port := layers.TCPPort(0)
	var config *string
	if len(parts) > 1 {
		nport, err := strconv.Atoi(parts[1])
		if err != nil {
			log.Fatalf("Bad port: %v", err)
		}
		port = layers.TCPPort(nport)
	}
	if len(parts) > 2 {
		config = &parts[2]
	}
	wirings = append(wirings, wiring{
		proto:  proto,
		port:   port,
		config: config,
	})
	return nil
}

var debug_circonus = flag.Bool("debug_circonus", false, "Debug CirconusMetrics")
var vflag = flag.Bool("v", false, "Show version information")
var quiet = flag.Bool("s", false, "Be quiet")
var apihost = flag.String("apihost", "", "Circonus API Hostname")
var apitoken = flag.String("apitoken", "", "Circonus API Token")
var instanceid = flag.String("instanceid", "", "This machine's unique identifier")
var submissionurl = flag.String("submissionurl", "", "Optional HTTPTrap URL")
var checkid = flag.Int("checkid", 0, "The Circonus check ID (not bundle id)")
var brokergroupid = flag.Int("brokergroupid", 0, "The broker group id")
var pprofNet = flag.Int("pprof_net", 0, "Port on which to listen for pprof")
var brokertag = flag.String("brokertag", "", "The broker tag for selection")

func main() {
	var localip_flag localip
	flag.Var(&localip_flag, "localip", "<ipaddress>")
	var registrations_flag regflag
	flag.Var(&registrations_flag, "wire", "<name>:<port>[:<config>]")
	flag.Parse()
	if *vflag {
		fmt.Printf("%s version %s\n", os.Args[0], version)
		os.Exit(0)
	}

	if *pprofNet > 0 {
		go func() {
			http.ListenAndServe("localhost:"+strconv.Itoa(*pprofNet), nil)
		}()
	}
	if *apitoken == "" {
		log.Printf("No Circonus API Token specified, no reporting will happen.")
	} else {
		cfg := &circonusgometrics.Config{}
		cfg.CheckManager.Check.InstanceId = *instanceid
		cfg.CheckManager.Check.SubmissionUrl = *submissionurl
		cfg.CheckManager.Check.Id = *checkid
		cfg.CheckManager.Broker.Id = *brokergroupid
		cfg.CheckManager.Broker.SelectTag = *brokertag
		cfg.CheckManager.Api.Url = *apihost
		cfg.CheckManager.Api.Token.Key = *apitoken
		cfg.Debug = *debug_circonus
		metrics, err := circonusgometrics.NewCirconusMetrics(cfg)
		if err != nil {
			log.Printf("Error initializing Circonus metrics, no reporting will happen. (%v)", err)
		} else {
			metrics.Start()
			wirelatency.SetMetrics(metrics)
		}
	}

	for _, w := range wirings {
		if err := wirelatency.RegisterTCPPort(w.port, w.proto, w.config); err != nil {
			log.Fatalf("Failed to register %v on port %v: %v", w.proto, w.port, err)
		}
	}
	prots := wirelatency.Protocols()
	mapping := wirelatency.PortMap()
	if len(mapping) == 0 {
		fmt.Printf("Usage:\n\t-wire <protocol>[:<port>[:<config>]]\n\n")
		fmt.Printf("No -wire <mapping> specified, available:\n")
		for protocol, _ := range prots {
			fmt.Printf("\t-wire %v\n", protocol)
		}
		fmt.Printf("\nplease specify at least one wire mapping.\n")
		fmt.Printf("\nUse -help for many more options.\n")
		os.Exit(2)
	}
	for port, twa := range mapping {
		config := (*twa).Config
		if !*quiet {
			if config == nil {
				log.Printf("\t*:%v -> %v", port, (*twa.Proto()).Name())
			} else {
				log.Printf("\t*:%v -> %v(%v)", port, (*twa.Proto()).Name(), *config)
			}
		}
	}
	wirelatency.Capture()
}
