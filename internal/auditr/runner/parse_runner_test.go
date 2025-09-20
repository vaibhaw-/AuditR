package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/vaibhaw-/AuditR/internal/auditr/parsers"
)

// fakeParser implements parsers.Parser for testing runParse.
type fakeParser struct {
	lines []struct {
		event *parsers.Event
		err   error
	}
	i int
}

func (f *fakeParser) ParseLine(ctx context.Context, line string) (*parsers.Event, error) {
	if f.i >= len(f.lines) {
		return nil, parsers.ErrSkipLine
	}
	item := f.lines[f.i]
	f.i++
	return item.event, item.err
}

// decodeEvents decodes NDJSON output into []*parsers.Event
func decodeEvents(out bytes.Buffer) ([]*parsers.Event, error) {
	var events []*parsers.Event
	dec := json.NewDecoder(&out)
	for dec.More() {
		var e parsers.Event
		if err := dec.Decode(&e); err != nil {
			return nil, err
		}
		events = append(events, &e)
	}
	return events, nil
}

func TestRunParse_NormalEvent(t *testing.T) {
	in := strings.NewReader("SOME SQL LINE\n")
	out := bytes.Buffer{}

	evt := &parsers.Event{
		EventID:   uuid.NewString(),
		DBSystem:  "postgres",
		QueryType: "SELECT",
	}
	parser := &fakeParser{lines: []struct {
		event *parsers.Event
		err   error
	}{{event: evt, err: nil}}}

	if err := RunParse(context.Background(), parser, in, &out, "postgres"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	events, err := decodeEvents(out)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].QueryType != "SELECT" {
		t.Errorf("expected SELECT, got %s", events[0].QueryType)
	}
}

func TestRunParse_SkipLine(t *testing.T) {
	in := strings.NewReader("NOISE LINE\n")
	out := bytes.Buffer{}

	parser := &fakeParser{lines: []struct {
		event *parsers.Event
		err   error
	}{{event: nil, err: parsers.ErrSkipLine}}}

	if err := RunParse(context.Background(), parser, in, &out, "postgres"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	events, err := decodeEvents(out)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if events[0].QueryType != "SKIP" {
		t.Errorf("expected SKIP, got %s", events[0].QueryType)
	}
	if events[0].Timestamp == "" {
		t.Errorf("expected non-empty timestamp for SKIP event")
	}
}

func TestRunParse_ParseError(t *testing.T) {
	in := strings.NewReader("BAD LINE\n")
	out := bytes.Buffer{}

	parser := &fakeParser{lines: []struct {
		event *parsers.Event
		err   error
	}{{event: nil, err: errors.New("boom")}}}

	err := RunParse(context.Background(), parser, in, &out, "postgres")
	if err == nil {
		t.Fatalf("expected fatal error, got nil")
	}

	events, _ := decodeEvents(out)
	if len(events) == 0 || events[0].QueryType != "PARSE_ERROR" {
		t.Errorf("expected PARSE_ERROR event, got %+v", events)
	}
	if events[0].Timestamp == "" {
		t.Errorf("expected non-empty timestamp for PARSE_ERROR event")
	}
}

func TestRunParse_NilEvent(t *testing.T) {
	in := strings.NewReader("LINE\n")
	out := bytes.Buffer{}

	parser := &fakeParser{lines: []struct {
		event *parsers.Event
		err   error
	}{{event: nil, err: nil}}} // simulate unexpected nil event

	if err := RunParse(context.Background(), parser, in, &out, "postgres"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	events, err := decodeEvents(out)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if events[0].QueryType != "PARSE_ERROR" {
		t.Errorf("expected PARSE_ERROR, got %s", events[0].QueryType)
	}
	if events[0].Timestamp == "" {
		t.Errorf("expected non-empty timestamp for PARSE_ERROR event")
	}
}
