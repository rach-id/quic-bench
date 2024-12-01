package trace

import (
	"time"
)

// P2PTables returns the list of tables that are used for p2p tracing.
func P2PTables() []string {
	return []string{
		TimedSentBytesTable,
		TimedReceivedBytesTable,
	}
}

const (
	TimedSentBytesTable = "timed_sent_bytes"
)

type TimedSentBytes struct {
	PeerID    string    `json:"peer_id"`
	Channel   byte      `json:"channel"`
	Bytes     int       `json:"bytes"`
	Time      time.Time `json:"time"`
	IPAddress string    `json:"ip_address"`
}

func (s TimedSentBytes) Table() string {
	return TimedSentBytesTable
}

func WriteTimedSentBytes(client *LocalTracer, peerID string, ipAddr string, channel byte, bytes int, t time.Time) {
	client.Write(TimedSentBytes{PeerID: peerID, Channel: channel, Bytes: bytes, Time: t, IPAddress: ipAddr})
}

const (
	TimedReceivedBytesTable = "timed_received_bytes"
)

type TimedReceivedBytes struct {
	PeerID    string    `json:"peer_id"`
	Channel   byte      `json:"channel"`
	Bytes     int       `json:"bytes"`
	Time      time.Time `json:"time"`
	IPAddress string    `json:"ip_address"`
}

func (s TimedReceivedBytes) Table() string {
	return TimedReceivedBytesTable
}

func WriteTimedReceivedBytes(client *LocalTracer, peerID string, ipAddr string, channel byte, bytes int, t time.Time) {
	client.Write(TimedReceivedBytes{PeerID: peerID, Channel: channel, Bytes: bytes, Time: t, IPAddress: ipAddr})
}
