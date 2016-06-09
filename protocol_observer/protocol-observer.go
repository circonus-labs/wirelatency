package main

import (
	"flag"
	"fmt"
"github.com/circonus-labs/circonus-gometrics"
	"github.com/circonus-labs/wirelatency"
	"github.com/google/gopacket/layers"
	"log"
	"os"
	"strconv"
	"strings"
)

type regflag struct{}

func (r *regflag) String() string {
	return "complex multiple values"
}
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

	if err := wirelatency.RegisterTCPPort(port, proto, config); err != nil {
		log.Fatalf("Failed to register %v on port %v: %v", proto, port, err)
	}

	return nil
}

var debug_circonus = flag.Bool("debug_circonus", false, "Debug CirconusMetrics")

var apihost = flag.String("apihost", "", "Circonus API Hostname")
var apitoken = flag.String("apitoken", "", "Circonus API Token")
var instanceid = flag.String("instanceid", "", "This machine's unique identifier")
var submissionurl = flag.String("submissionurl", "", "Optional HTTPTrap URL")
var checkid = flag.Int("checkid", 0, "The Circonus check ID (not bundle id)")
var brokergroupid = flag.Int("brokergroupid", 0, "The broker group id")
//var brokertag = flag.String("brokertag", "", "The broker tag for selection")

func main() {
	var registrations_flag regflag
	flag.Var(&registrations_flag, "wire", "<name>:<port>[:<config>]")
	flag.Parse()

     metrics :=  circonusgometrics.NewCirconusMetrics()
     if *apitoken == "" {
        flag.Usage()
        os.Exit(2)
     }
     if *apihost != "" { metrics.ApiHost = *apihost }
     if *instanceid != "" { metrics.InstanceId = *instanceid }
     if *submissionurl != "" { metrics.SubmissionUrl = *submissionurl }
     if *checkid > 0 { metrics.CheckId = *checkid }
     if *brokergroupid > 0 { metrics.BrokerGroupId = *brokergroupid }
     // if *brokertag != "" { metrics.BrokerSelectTag = *brokertag }
     metrics.ApiToken = *apitoken
     metrics.Debug = *debug_circonus
     metrics.Start()
     wirelatency.SetMetrics(metrics)

	prots := wirelatency.Protocols()
	mapping := wirelatency.PortMap()
	if len(mapping) == 0 {
		fmt.Printf("Usage:\n\t-wire <protocol>[:<port>[:<config>]]\n\n")
		fmt.Printf("No -wire <mapping> specified, available:\n")
		for protocol, _ := range prots {
			fmt.Printf("\t-wire %v\n", protocol)
		}
		fmt.Printf("\nplease specify at least one mapping.\n")
		os.Exit(2)
	}
	for port, twa := range mapping {
		config := (*twa).Config
		if config == nil {
			log.Printf("\t*:%v -> %v", port, (*twa.Proto()).Name())
		} else {
			log.Printf("\t*:%v -> %v(%v)", port, (*twa.Proto()).Name(), *config)
		}
	}
	wirelatency.Capture()
}
