package trace

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"strings"
	"time"
)

// Event wraps some trace data with metadata that dictates the table and things
// like the chainID and nodeID.
type Event[T any] struct {
	ChainID   string    `json:"chain_id"`
	NodeID    string    `json:"node_id"`
	Table     string    `json:"table"`
	Timestamp time.Time `json:"timestamp"`
	Msg       T         `json:"msg"`
}

// NewEvent creates a new Event with the given chainID, nodeID, table, and msg.
// It adds the current time as the timestamp.
func NewEvent[T any](table string, msg T) Event[T] {
	return Event[T]{
		Table:     table,
		Msg:       msg,
		Timestamp: time.Now(),
	}
}

// LocalTracer saves all of the events passed to the retuen channel to files
// based on their "type" (a string field in the event). Each type gets its own
// file. The internals are purposefully not *explicitly* thread safe to avoid the
// overhead of locking with each event save. Only pass events to the returned
// channel. Call CloseAll to close all open files.
type LocalTracer struct {
	// fileMap maps tables to their open files files are threadsafe, but the map
	// is not. Therefore don't create new files after initialization to remain
	// threadsafe.
	fileMap map[string]*bufferedFile
	// canal is a channel for all events that are being written. It acts as an
	// extra buffer to avoid blocking the caller when writing to files.
	canal chan Event[Entry]
}

// NewLocalTracer creates a struct that will save all of the events passed to
// the retuen channel to files based on their "table" (a string field in the
// event). Each type gets its own file. The internal are purposefully not thread
// safe to avoid the overhead of locking with each event save. Only pass events
// to the returned channel. Call CloseAll to close all open files. Goroutine to
// save events is started in this function.
func NewLocalTracer(ctx context.Context) (*LocalTracer, error) {
	fm := make(map[string]*bufferedFile)
	p := path.Join(".", "data", "traces")
	for _, table := range splitAndTrimEmpty(DefaultTracingTables, ",", " ") {
		fileName := fmt.Sprintf("%s/%s.jsonl", p, table)
		err := os.MkdirAll(p, 0700)
		if err != nil {
			return nil, fmt.Errorf("failed to create directory %s: %w", p, err)
		}
		file, err := os.OpenFile(fileName, os.O_APPEND|os.O_CREATE|os.O_RDWR, 0644)
		if err != nil {
			return nil, fmt.Errorf("failed to open or create file %s: %w", fileName, err)
		}
		fm[table] = newbufferedFile(ctx, file)
	}

	lt := &LocalTracer{
		fileMap: fm,
		canal:   make(chan Event[Entry], 6000),
	}

	go lt.drainCanal()
	return lt, nil
}

func (lt *LocalTracer) Write(e Entry) {
	if !lt.IsCollecting(e.Table()) {
		return
	}
	lt.canal <- NewEvent(e.Table(), e)
}

// ReadTable returns a file for the given table. If the table is not being
// collected, an error is returned. The caller should not close the file.
func (lt *LocalTracer) readTable(table string) (*os.File, func() error, error) {
	bf, has := lt.getFile(table)
	if !has {
		return nil, func() error { return nil }, fmt.Errorf("table %s not found", table)
	}

	return bf.File()
}

func (lt *LocalTracer) IsCollecting(table string) bool {
	_, has := lt.getFile(table)
	return has
}

// getFile gets a file for the given type. This method is purposely
// not thread-safe to avoid the overhead of locking with each event save.
func (lt *LocalTracer) getFile(table string) (*bufferedFile, bool) {
	f, has := lt.fileMap[table]
	return f, has
}

// saveEventToFile marshals an Event into JSON and appends it to a file named after the event's Type.
func (lt *LocalTracer) saveEventToFile(event Event[Entry]) error {
	file, has := lt.getFile(event.Table)
	if !has {
		return fmt.Errorf("table %s not found", event.Table)
	}

	eventJSON, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal event: %v", err)
	}

	if _, err := file.Write(append(eventJSON, '\n')); err != nil {
		return fmt.Errorf("failed to write event to file: %v", err)
	}

	return nil
}

// draincanal takes a variadic number of channels of Event pointers and drains them into files.
func (lt *LocalTracer) drainCanal() {
	// purposefully do not lock, and rely on the channel to provide sync
	// actions, to avoid overhead of locking with each event save.
	for ev := range lt.canal {
		if err := lt.saveEventToFile(ev); err != nil {
			fmt.Printf("failed to save event to file %v", err)
		}
	}
}

// Stop optionally uploads and closes all open files.
func (lt *LocalTracer) Stop() {
	for _, file := range lt.fileMap {
		err := file.Close()
		if err != nil {
			fmt.Printf("failed to close file %v", err)
		}
	}
}

// splitAndTrimEmpty slices s into all subslices separated by sep and returns a
// slice of the string s with all leading and trailing Unicode code points
// contained in cutset removed. If sep is empty, SplitAndTrim splits after each
// UTF-8 sequence. First part is equivalent to strings.SplitN with a count of
// -1.  also filter out empty strings, only return non-empty strings.
//
// NOTE: this is copy pasted from the config package to avoid a circular
// dependency. See the function of the same name for tests.
func splitAndTrimEmpty(s, sep, cutset string) []string {
	if s == "" {
		return []string{}
	}

	spl := strings.Split(s, sep)
	nonEmptyStrings := make([]string, 0, len(spl))
	for i := 0; i < len(spl); i++ {
		element := strings.Trim(spl[i], cutset)
		if element != "" {
			nonEmptyStrings = append(nonEmptyStrings, element)
		}
	}
	return nonEmptyStrings
}
