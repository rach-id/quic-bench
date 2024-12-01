package trace

import (
	"strings"
)

var DefaultTracingTables = strings.Join(P2PTables(), ",")

type TransferType int

const (
	Download TransferType = iota
	Upload
)

func (t TransferType) String() string {
	switch t {
	case Download:
		return "download"
	case Upload:
		return "upload"
	default:
		return "unknown"
	}
}
