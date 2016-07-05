package wirelatency

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"flag"
	"fmt"
	"github.com/golang/snappy"
	"io/ioutil"
	"log"
	"time"
)

var debug_kafka = flag.Bool("debug_kafka", false, "Debug kafka reassembly")

type kafkaConfig struct {
	dummy int
}

func kafkaConfigParser(c *string) interface{} {
	return nil
	config := kafkaConfig{}
	return config
}

const (
	kafka_ProduceRequest          = int16(0)
	kafka_FetchRequest            = int16(1)
	kafka_OffsetRequest           = int16(2)
	kafka_MetadataRequest         = int16(3)
	kafka_Control4                = int16(4)
	kafka_Control5                = int16(5)
	kafka_Control6                = int16(6)
	kafka_Control7                = int16(7)
	kafka_OffsetCommitRequest     = int16(8)
	kafka_OffsetFetchRequest      = int16(9)
	kafka_GroupCoordinatorRequest = int16(10)
	kafka_JoinGroupRequest        = int16(11)
	kafka_HeartbeatRequest        = int16(12)
	kafka_LeaveGroupRequest       = int16(13)
	kafka_SyncGroupRequest        = int16(14)
	kafka_DescribeGroupsRequest   = int16(15)
	kafka_ListGroupsRequest       = int16(16)

	kafka_NoError                          = int16(0)
	kafka_Unknown                          = int16(-1)
	kafka_OffsetOutOfRange                 = int16(1)
	kafka_InvalidMessage                   = int16(2)
	kafka_UnknownTopicOrPartition          = int16(3)
	kafka_InvalidMessageSize               = int16(4)
	kafka_LeaderNotAvailable               = int16(5)
	kafka_NotLeaderForPartition            = int16(6)
	kafka_RequestTimedOut                  = int16(7)
	kafka_BrokerNotAvailable               = int16(8)
	kafka_ReplicaNotAvailable              = int16(9)
	kafka_MessageSizeTooLarge              = int16(10)
	kafka_StaleControllerEpochCode         = int16(11)
	kafka_OffsetMetadataTooLargeCode       = int16(12)
	kafka_GroupLoadInProgressCode          = int16(14)
	kafka_GroupCoordinatorNotAvailableCode = int16(15)
	kafka_NotCoordinatorForGroupCode       = int16(16)
	kafka_InvalidTopicCode                 = int16(17)
	kafka_RecordListTooLargeCode           = int16(18)
	kafka_NotEnoughReplicasCode            = int16(19)
	kafka_NotEnoughReplicasAfterAppendCode = int16(20)
	kafka_InvalidRequiredAcksCode          = int16(21)
	kafka_IllegalGenerationCode            = int16(22)
	kafka_InconsistentGroupProtocolCode    = int16(23)
	kafka_InvalidGroupIdCode               = int16(24)
	kafka_UnknownMemberIdCode              = int16(25)
	kafka_InvalidSessionTimeoutCode        = int16(26)
	kafka_RebalanceInProgressCode          = int16(27)
	kafka_InvalidCommitOffsetSizeCode      = int16(28)
	kafka_TopicAuthorizationFailedCode     = int16(29)
	kafka_GroupAuthorizationFailedCode     = int16(30)
	kafka_ClusterAuthorizationFailedCode   = int16(31)

	kafka_retainedPayloadSize = int(1024)
)

type kafka_message struct {
	parent_compression int8
	offset             int64
	length             int32
	crc                int32
	magic_byte         int8
	attributes         int8
	timestamp          time.Time
	key                []byte
	value              []byte

	value_len int
}
type kafka_partition_set struct {
	partition  int32
	record_set []byte
	messages   []kafka_message
}
type kafka_produce_req_partition struct {
	pset kafka_partition_set
}
type kafka_produce_req_topic struct {
	topic      string
	partitions []kafka_produce_req_partition
}
type kafka_produce_request struct {
	requiredacks int16
	timeout      int32
	topics       []kafka_produce_req_topic
}
type kafka_response_frame struct {
	correlationid int32
}
type kafka_fetch_partition struct {
	pset           kafka_partition_set
	error_code     int16
	high_watermark int64
}
type kafka_fetch_topic struct {
	topic      string
	partitions []kafka_fetch_partition
}
type kafka_fetch_response struct {
	throttle_time_ms int32
	topics           []kafka_fetch_topic
}

type kafka_produce_partition struct {
	partition  int32
	error_code int16
	offset     int64
	timestamp  time.Time
}
type kafka_produce_topic struct {
	topic      string
	partitions []kafka_produce_partition
}
type kafka_produce_response struct {
	throttle_time_ms int32
	topics           []kafka_produce_topic
}

var global_kafka_fetch kafka_fetch_response
var global_kafka_produce kafka_produce_response

type kafka_request_frame struct {
	apikey        int16
	apiversion    int16
	correlationid int32
	clientid      string
}
type kafka_frame struct {
	inbound  bool
	complete bool
	so_far   int

	request          kafka_request_frame
	response         kafka_response_frame
	produce_request  *kafka_produce_request
	produce_response *kafka_produce_response
	fetch_response   *kafka_fetch_response

	length       int32
	length_bytes [4]byte
	payload      []byte
	truncated    bool // don't use the payload, it's not all there

	//
	timestamp      time.Time
	latency        time.Duration
	response_bytes int
}
type kafka_Parser struct {
	factory        *kafka_ParserFactory
	stream         map[int32]*kafka_frame
	request_frame  kafka_frame
	response_frame kafka_frame
}

func kafka_frame_ApiName(code int16) (string, bool) {
	switch code {
	case kafka_ProduceRequest:
		return "ProduceRequest", true
	case kafka_FetchRequest:
		return "FetchRequest", true
	case kafka_OffsetRequest:
		return "OffsetRequest", true
	case kafka_MetadataRequest:
		return "MetadataRequest", true
	case kafka_Control4:
		return "Control4", true
	case kafka_Control5:
		return "Control5", true
	case kafka_Control6:
		return "Control6", true
	case kafka_Control7:
		return "Control7", true
	case kafka_OffsetCommitRequest:
		return "OffsetCommitRequest", true
	case kafka_OffsetFetchRequest:
		return "OffsetFetchRequest", true
	case kafka_GroupCoordinatorRequest:
		return "GroupCoordinatorRequest", true
	case kafka_JoinGroupRequest:
		return "JoinGroupRequest", true
	case kafka_HeartbeatRequest:
		return "HeartbeatRequest", true
	case kafka_LeaveGroupRequest:
		return "LeaveGroupRequest", true
	case kafka_SyncGroupRequest:
		return "SyncGroupRequest", true
	case kafka_DescribeGroupsRequest:
		return "DescribeGroupsRequest", true
	case kafka_ListGroupsRequest:
		return "ListGroupsRequest", true
	}
	return fmt.Sprintf("unknown:%d", code), false
}
func (f *kafka_frame) ApiName() string {
	if f.inbound {
		name, _ := kafka_frame_ApiName(f.request.apikey)
		return name
	}
	return "Response"
}
func (f *kafka_frame) copy() *kafka_frame {
	f_copy := *f
	f_copy.payload = nil
	return &f_copy
}
func (p *kafka_Parser) report_pset(f *kafka_frame, pset *kafka_partition_set, topic string, partition int32, now time.Time) int {
	n_msgs := 0
	if pset.messages != nil {
		for _, m := range pset.messages {
			n_msgs++
			if f.request.apiversion > 0 && (f.produce_request == nil || f.produce_request.requiredacks != 0) {
				mlat := now.Sub(m.timestamp)
				wl_track_float64("seconds", float64(mlat)/1000000000.0, f.ApiName()+"`_aggregate`message`latency")
				wl_track_float64("seconds", float64(mlat)/1000000000.0, f.ApiName()+"`"+topic+"`message`latency")
			}
			if m.value != nil {
				wl_track_int64("bytes", int64(m.value_len), f.ApiName()+"`_aggregate`message`size")
				wl_track_int64("bytes", int64(m.value_len), f.ApiName()+"`"+topic+"`message`size")
			}
		}
	}
	return n_msgs
}
func (p *kafka_Parser) report(stream *tcpTwoWayStream, f *kafka_frame, now time.Time) {
	latency := &f.latency
	if f.request.apikey == kafka_ProduceRequest &&
		f.produce_request != nil &&
		f.produce_request.requiredacks == 0 {
		latency = nil
		n_msgs := 0
		for _, topic := range f.produce_request.topics {
			p_msgs := 0
			for _, part := range topic.partitions {
				p_msgs += p.report_pset(f, &part.pset, topic.topic, part.pset.partition, now)
			}
			wl_track_int64("messages", int64(p_msgs), f.ApiName()+"`"+topic.topic+"`messages")
			wl_track_int64("bytes", int64(f.length), f.ApiName()+"`"+topic.topic+"`bytes")
			n_msgs += p_msgs
		}
		wl_track_int64("messages", int64(n_msgs), f.ApiName()+"`_aggregate`messages")
		wl_track_int64("bytes", int64(f.length), f.ApiName()+"`_aggregate`bytes")
	}
	if latency != nil {
		wl_track_float64("seconds", float64(*latency)/1000000000.0, f.ApiName()+"`latency")
	}
	if f.produce_response != nil || f.fetch_response != nil {
		n_msgs := 0
		if f.produce_response != nil && f.produce_request != nil {
			for _, topic := range f.produce_response.topics {
				p_msgs := 0
				var rparts []kafka_produce_req_partition
				for _, rtopic := range f.produce_request.topics {
					if topic.topic == rtopic.topic {
						rparts = rtopic.partitions
					}
				}
				for _, part := range topic.partitions {
					for _, rpart := range rparts {
						if part.partition == rpart.pset.partition {
							p_msgs += p.report_pset(f, &rpart.pset, topic.topic, part.partition, now)
						}
					}
				}
				wl_track_int64("messages", int64(p_msgs), f.ApiName()+"`"+topic.topic+"`messages")
				wl_track_int64("bytes", int64(f.length), f.ApiName()+"`"+topic.topic+"`bytes")
				n_msgs += p_msgs
			}
			if f.request.apiversion > 0 {
				wl_track_float64("seconds", float64(f.produce_response.throttle_time_ms)/1000.0, f.ApiName()+"`throttle_time")
			}
		} else if f.fetch_response != nil {
			for _, topic := range f.fetch_response.topics {
				p_msgs := 0
				for _, part := range topic.partitions {
					p_msgs += p.report_pset(f, &part.pset, topic.topic, part.pset.partition, now)
				}
				wl_track_int64("messages", int64(p_msgs), f.ApiName()+"`"+topic.topic+"`messages")
				wl_track_int64("bytes", int64(f.length), f.ApiName()+"`"+topic.topic+"`bytes")
				n_msgs += p_msgs
			}
		}
		wl_track_int64("messages", int64(n_msgs), f.ApiName()+"`_aggregate`messages")
		wl_track_int64("bytes", int64(f.length), f.ApiName()+"`_aggregate`bytes")
	}
}

var snappyJavaMagic = []byte("\x82SNAPPY\x00")

func (p *kafka_Parser) expand_messages(stream *tcpTwoWayStream, in []kafka_message, apiversion int16, pc int8, data []byte) []kafka_message {
	if in == nil {
		in = make([]kafka_message, 0, 10)
	}
	used := 0
	for used < len(data) {
		m := kafka_message{}
		m.parent_compression = pc
		if m.offset, used = kafka_read_int64(data, used); used < 0 {
			stream.factory.Error("bad_packet")
			return in
		}
		m_len := int32(0)
		if m_len, used = kafka_read_int32(data, used); used < 0 || m_len < 1 {
			stream.factory.Error("bad_packet")
			return in
		}
		expected_used := used + int(m_len)
		if m.crc, used = kafka_read_int32(data, used); used < 0 {
			stream.factory.Error("bad_packet")
			return in
		}
		if m.magic_byte, used = kafka_read_int8(data, used); used < 0 {
			stream.factory.Error("bad_packet")
			return in
		}
		if m.attributes, used = kafka_read_int8(data, used); used < 0 {
			stream.factory.Error("bad_packet")
			return in
		}
		if apiversion > 0 {
			var timestamp int64
			if timestamp, used = kafka_read_int64(data, used); used < 0 {
				stream.factory.Error("bad_packet")
				return in
			}
			m.timestamp = time.Unix(timestamp/1000, (timestamp%1000)*1000000)
		}
		if m.key, used = kafka_read_bytes(data, used); used < 0 {
			stream.factory.Error("bad_packet")
			return in
		}
		if m.value, used = kafka_read_bytes(data, used); used < 0 {
			stream.factory.Error("bad_packet")
			return in
		}
		m.value_len = len(m.value)
		switch m.attributes & 0x7 {
		case 0:
			in = append(in, m)
		case 1: //gzip
			if compressed, err := gzip.NewReader(bytes.NewReader(m.value)); err == nil {
				defer compressed.Close()
				if data, rerr := ioutil.ReadAll(compressed); rerr == nil {
					in = p.expand_messages(stream, in, apiversion, 2, data)
				} else {
					stream.factory.Error("bad_packet:gzip")
				}
			}
		case 2: //snappy
			if !bytes.HasPrefix(m.value, snappyJavaMagic) {
				if data, err := snappy.Decode(nil, m.value); err == nil {
					in = p.expand_messages(stream, in, apiversion, 2, data)
				} else {
					stream.factory.Error("bad_packet:snappy")
					if *debug_kafka {
						log.Printf("[DEBUG] snappy failed: %v", err)
					}
				}
			} else if binary.BigEndian.Uint32(m.value[8:12]) == 1 {
				data := make([]byte, 0, len(m.value))
				var chunk []byte
				for i := 16; i < len(m.value); {
					n := int(binary.BigEndian.Uint32(m.value[i : i+4]))
					i += 4
					chunk, err := snappy.Decode(chunk, m.value[i:i+n])
					if err != nil {
						stream.factory.Error("bad_packet:snappy")
						data = nil
						break
					}
					i += n
					if data != nil {
						data = append(data, chunk...)
					}
				}
				if data != nil {
					in = p.expand_messages(stream, in, apiversion, 2, data)
				}
			}
		case 3: //lz4
			// todo golang lz4 implementations are "meh" and this is actually lz4f
		}

		if used != expected_used {
			stream.factory.Error("bad_packet")
			if *debug_kafka {
				log.Printf("[DEBUG] corrupted message?")
			}
			used = expected_used
		}
	}
	return in
}
func (p *kafka_Parser) validateIn(stream *tcpTwoWayStream, f *kafka_frame) (bool, bool) {
	// parse our request header
	used := 0
	if f.request.apikey, used = kafka_read_int16(f.payload, used); used < 0 {
		stream.factory.Error("bad_packet")
		return false, false
	}
	if f.request.apiversion, used = kafka_read_int16(f.payload, used); used < 0 {
		stream.factory.Error("bad_packet")
		return false, false
	}
	if f.request.correlationid, used = kafka_read_int32(f.payload, used); used < 0 {
		stream.factory.Error("bad_packet")
		return false, false
	}
	if f.request.clientid, used = kafka_read_string(f.payload, used); used < 0 {
		stream.factory.Error("bad_packet")
		return false, false
	}

	expect_response := true
	_, valid := kafka_frame_ApiName(f.request.apikey)
	// if it is a publish request with ack of 0, there will be no response
	if f.request.apikey == kafka_ProduceRequest {
		pr := kafka_produce_request{}
		if pr.requiredacks, used = kafka_read_int16(f.payload, used); used < 0 {
			stream.factory.Error("bad_packet")
			return false, false
		}
		if pr.timeout, used = kafka_read_int32(f.payload, used); used < 0 {
			stream.factory.Error("bad_packet")
			return false, false
		}
		var n_topics int32
		if n_topics, used = kafka_read_int32(f.payload, used); used < 0 {
			stream.factory.Error("bad_packet")
			return false, false
		}
		pr.topics = make([]kafka_produce_req_topic, n_topics)
		for i := int32(0); i < n_topics; i++ {
			if pr.topics[i].topic, used = kafka_read_string(f.payload, used); used < 0 {
				stream.factory.Error("bad_packet")
				return false, false
			}
			var n_partitions int32
			if n_partitions, used = kafka_read_int32(f.payload, used); used < 0 {
				stream.factory.Error("bad_packet")
				return false, false
			}
			pr.topics[i].partitions = make([]kafka_produce_req_partition, n_partitions)
			for p_i := int32(0); p_i < n_partitions; p_i++ {
				part := &pr.topics[i].partitions[p_i]
				pset := &part.pset
				if pset.partition, used = kafka_read_int32(f.payload, used); used < 0 {
					stream.factory.Error("bad_packet")
					return false, false
				}
				if pset.record_set, used = kafka_read_bytes(f.payload, used); used < 0 {
					stream.factory.Error("bad_packet")
					return false, false
				}
				pset.messages = p.expand_messages(stream, pset.messages, f.request.apiversion, 0, pset.record_set)
				// Zip through the messages and set their timestamps to the frame's timestamp
				// we do this b/c we care about produce latencies, not timestamp latencies
				for _, message := range pset.messages {
					message.timestamp = f.timestamp
				}
			}
		}
		if pr.requiredacks == 0 {
			expect_response = false
			p.report(stream, f, f.timestamp)
		}
		f.produce_request = &pr
	}
	return valid, expect_response
}
func (p *kafka_Parser) validateOut(stream *tcpTwoWayStream, f *kafka_frame) bool {
	used := 0
	if f.response.correlationid, used = kafka_read_int32(f.payload, used); used < 0 {
		stream.factory.Error("bad_packet")
		return false
	}
	req, ok := p.stream[f.response.correlationid]
	if !ok {
		stream.factory.Error("uncorrelated_response")
		return false
	}
	switch req.request.apikey {
	case kafka_FetchRequest:
		global_kafka_fetch.throttle_time_ms = -1
		if req.request.apiversion > 0 {
			global_kafka_fetch.throttle_time_ms, used = kafka_read_int32(f.payload, used)
			if used < 0 {
				stream.factory.Error("bad_packet")
				return false
			}
		}
		var n_topics int32
		n_topics, used = kafka_read_int32(f.payload, used)
		if used < 0 {
			stream.factory.Error("bad_packet")
			return false
		}
		global_kafka_fetch.topics = make([]kafka_fetch_topic, n_topics)
		for i := int32(0); i < n_topics; i++ {
			var n_partitions int32
			if global_kafka_fetch.topics[i].topic, used = kafka_read_string(f.payload, used); used < 0 {
				stream.factory.Error("bad_packet")
				return false
			}
			if n_partitions, used = kafka_read_int32(f.payload, used); used < 0 {
				stream.factory.Error("bad_packet")
				return false
			}
			global_kafka_fetch.topics[i].partitions = make([]kafka_fetch_partition, n_partitions)
			for p_i := int32(0); p_i < n_partitions; p_i++ {
				part := &global_kafka_fetch.topics[i].partitions[p_i]
				pset := &part.pset
				if pset.partition, used = kafka_read_int32(f.payload, used); used < 0 {
					stream.factory.Error("bad_packet")
					return false
				}
				if part.error_code, used = kafka_read_int16(f.payload, used); used < 0 {
					stream.factory.Error("bad_packet")
					return false
				}
				if part.high_watermark, used = kafka_read_int64(f.payload, used); used < 0 {
					stream.factory.Error("bad_packet")
					return false
				}
				if pset.record_set, used = kafka_read_bytes(f.payload, used); used < 0 {
					stream.factory.Error("bad_packet")
					return false
				}
				pset.messages = p.expand_messages(stream, pset.messages, req.request.apiversion, 0, pset.record_set)
			}
		}
		req.fetch_response = &global_kafka_fetch
	case kafka_ProduceRequest:
		global_kafka_produce.throttle_time_ms = -1
		var n_topics int32
		if n_topics, used = kafka_read_int32(f.payload, used) ; used < 0 {
			stream.factory.Error("bad_packet")
			return false
		}
		global_kafka_produce.topics = make([]kafka_produce_topic, n_topics)
		for i := int32(0); i < n_topics; i++ {
			var n_partitions int32
			if global_kafka_produce.topics[i].topic, used = kafka_read_string(f.payload, used); used < 0 {
				stream.factory.Error("bad_packet")
				return false
			}
			if n_partitions, used = kafka_read_int32(f.payload, used); used < 0 {
				stream.factory.Error("bad_packet")
				return false
			}
			global_kafka_produce.topics[i].partitions = make([]kafka_produce_partition, n_partitions)
			for p := int32(0); p < n_partitions; p++ {
				part := &global_kafka_produce.topics[i].partitions[p]
				if part.partition, used = kafka_read_int32(f.payload, used); used < 0 {
					stream.factory.Error("bad_packet")
					return false
				}
				if part.error_code, used = kafka_read_int16(f.payload, used); used < 0 {
					stream.factory.Error("bad_packet")
					return false
				}
				if part.offset, used = kafka_read_int64(f.payload, used); used < 0 {
					stream.factory.Error("bad_packet")
					return false
				}
				if req.request.apiversion > 1 {
					var timestamp int64
					if timestamp, used = kafka_read_int64(f.payload, used); used < 0 {
						stream.factory.Error("bad_packet")
						return false
					}
					if timestamp == -1 {
						part.timestamp = time.Time{}
					} else {
						part.timestamp = time.Unix(timestamp/1000, (timestamp%1000)*1000000)
					}
				}
			}
		}
		if req.request.apiversion > 0 {
			if global_kafka_fetch.throttle_time_ms, used = kafka_read_int32(f.payload, used); used < 0 {
				stream.factory.Error("bad_packet")
				return false
			}
		}
		req.produce_response = &global_kafka_produce
	}
	return true
}
func (f *kafka_frame) init() {
	f.complete = false
	f.so_far = 0
	f.request.apikey = -1
	f.request.apiversion = -1
	f.request.correlationid = -1
	f.request.clientid = ""
	f.fetch_response = nil
	f.produce_request = nil
	f.produce_response = nil
	f.timestamp = time.Time{}
	f.latency = 0
	f.length = 0
	f.truncated = false
	if f.payload == nil || cap(f.payload) != kafka_retainedPayloadSize {
		f.payload = make([]byte, 0, kafka_retainedPayloadSize)
	}
	f.payload = f.payload[:0]
}

// Takes "more" data in and attempts to complete the frame
// returns complete if the frame is complete. Always returns
// the number of bytes of the passed data used.  used should
// be the entire data size if frame is incomplete
// If things go off the rails unrecoverably, used = -1 is returned
func (f *kafka_frame) fillFrame(seen time.Time, data []byte) (complete bool, used int) {
	if len(data) < 1 {
		return false, 0
	}
	if f.so_far == 0 {
		f.timestamp = seen
	}
	// Next four bytes are the length (inclusive of the four bytes?!)
	for ; used < len(data) && f.so_far < 4; f.so_far, used = f.so_far+1, used+1 {
		f.length_bytes[f.so_far] = data[used]
		if f.so_far == 3 {
			f.length = int32(binary.BigEndian.Uint32(f.length_bytes[:]))
		}
	}
	if f.so_far < 4 {
		return false, used
	}

	// Now we read in the legnth
	remaining := f.length - (int32(f.so_far) - 4)
	to_append := remaining // how much we're actually reading
	if int32(len(data)-used) < remaining {
		// not complete
		to_append = int32(len(data) - used)
	}
	capped_append := to_append // how much we're actually writing
	if len(f.payload)+int(to_append) > cap(f.payload) {
		capped_append = int32(cap(f.payload) - len(f.payload))
		f.truncated = true
	}
	if capped_append > 0 {
		f.payload = append(f.payload, data[used:(used+int(capped_append))]...)
	}
	used = used + int(to_append)
	f.so_far = f.so_far + int(to_append)
	if remaining == to_append {
		f.complete = true
		if *debug_kafka {
			log.Printf("[DEBUG] frame completed")
		}
		return true, used
	}
	if *debug_kafka {
		log.Printf("[DEBUG] frame pending")
	}
	return false, used
}
func (p *kafka_Parser) flushStream() {
	p.stream = make(map[int32]*kafka_frame)
}

func kafka_read_int8(data []byte, used int) (int8, int) {
	if len(data) > used+0 {
		return int8(data[used]), used + 1
	}
	return int8(-1), -1
}
func kafka_read_int16(data []byte, used int) (int16, int) {
	if len(data) > used+1 {
		return int16(binary.BigEndian.Uint16(data[used:])), used + 2
	}
	return int16(-1), -1
}
func kafka_read_int32(data []byte, used int) (int32, int) {
	if len(data) > used+3 {
		return int32(binary.BigEndian.Uint32(data[used:])), used + 4
	}
	return int32(-1), -1
}
func kafka_read_int64(data []byte, used int) (int64, int) {
	if len(data) > used+7 {
		return int64(binary.BigEndian.Uint64(data[used:])), used + 8
	}
	return int64(-1), -1
}
func kafka_read_string(data []byte, used int) (string, int) {
	var slen int16
	slen, used = kafka_read_int16(data, used)
	if used < 0 || len(data) < used+int(slen) {
		return "", -1
	}
	return string(data[used : used+int(slen)]), used + int(slen)
}
func kafka_read_bytes(data []byte, used int) ([]byte, int) {
	slen, used := kafka_read_int32(data, used)
	if used < 0 {
		return nil, -1
	}
	// -1 is a nil string
	if slen == -1 {
		return nil, used
	}

	if len(data) < used+int(slen) {
		return nil, -1
	}
	return data[used : used+int(slen)], used + int(slen)
}

func (p *kafka_Parser) reset() {
	p.stream = make(map[int32]*kafka_frame)
	p.request_frame.init()
	p.response_frame.init()
}
func (p *kafka_Parser) InBytes(stream *tcpTwoWayStream, seen time.Time, data []byte) bool {
	// build a request
	for {
		if len(data) == 0 {
			return true
		}
		if complete, used := p.request_frame.fillFrame(seen, data); complete {
			f := &p.request_frame
			valid, expect_response := p.validateIn(stream, f)
			if !valid {
				if *debug_kafka {
					log.Printf("[DEBUG] <- BAD FRAME: %v", p.request_frame.ApiName())
				}
				p.reset()
				return true
			}
			if expect_response {
				p.stream[f.request.correlationid] = f.copy()
			} else {
				p.report(stream, f, seen)
			}
			data = data[used:]
			p.request_frame.init()
		} else if used < 0 {
			if *debug_kafka {
				log.Printf("[DEBUG] <- BAD READ IN: %v", used)
			}
			p.reset()
			return true
		} else if !complete {
			return true
		}
	}
}
func (p *kafka_Parser) OutBytes(stream *tcpTwoWayStream, seen time.Time, data []byte) bool {
	for {
		if len(data) == 0 {
			return true
		}
		if complete, used := p.response_frame.fillFrame(seen, data); complete {
			f := &p.response_frame
			if !p.validateOut(stream, f) {
				if *debug_kafka {
					log.Printf("[DEBUG] -> BAD FRAME: %v", p.request_frame.ApiName())
				}
				p.reset()
				return true
			}
			if *debug_kafka {
				log.Printf("[DEBUG] -> %v [%v]", f.ApiName(), used)
			}
			if req, ok := p.stream[f.response.correlationid]; ok {
				req.latency = seen.Sub(req.timestamp)
				delete(p.stream, f.response.correlationid)
				if *debug_kafka {
					log.Printf("[DEBUG] %v -> %v\nREQUEST: %+v\n", req.ApiName(), seen.Sub(req.timestamp), req)
				}
				p.report(stream, req, seen)
			}

			data = data[used:]
			p.response_frame.init()
		} else if used < 0 {
			if *debug_kafka {
				log.Printf("[DEBUG] -> BAD READ OUT: %v", used)
			}
			p.reset()
			return true
		} else if !complete {
			return true
		}
	}
}
func (p *kafka_Parser) ManageIn(stream *tcpTwoWayStream) {
	panic("kafka wirelatency parser is not async")
}
func (p *kafka_Parser) ManageOut(stream *tcpTwoWayStream) {
	panic("kafka wirelatency parser is not async")
}

type kafka_ParserFactory struct {
	parsed map[uint16]string
}

func (f *kafka_ParserFactory) New() TCPProtocolInterpreter {
	p := kafka_Parser{}
	p.factory = f
	p.request_frame.inbound = true
	p.reset()
	return &p
}
func init() {
	factory := &kafka_ParserFactory{}
	kafkaProt := &TCPProtocol{
		name:        "kafka",
		defaultPort: 9093,
		inFlight:    true,
		Config:      kafkaConfigParser,
	}
	kafkaProt.interpFactory = factory
	RegisterTCPProtocol(kafkaProt)
}
