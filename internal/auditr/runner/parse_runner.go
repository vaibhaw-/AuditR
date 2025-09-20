package runner

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/google/uuid"
	"github.com/vaibhaw-/AuditR/internal/auditr/logger"
	"github.com/vaibhaw-/AuditR/internal/auditr/parsers"
)

// RunParse is the core loop for parsing audit logs.
// It is factored out from the Cobra command so it can be unit tested.
func RunParse(ctx context.Context, p parsers.Parser, in io.Reader, out io.Writer, db string) error {
	log := logger.L()

	scanner := bufio.NewScanner(in)
	enc := json.NewEncoder(out)

	for scanner.Scan() {
		line := scanner.Text()

		evt, err := p.ParseLine(ctx, line)
		if err != nil {
			if errors.Is(err, parsers.ErrSkipLine) {
				ts := time.Now().UTC().Format(time.RFC3339Nano)
				raw := line

				skipEvt := &parsers.Event{
					EventID:   uuid.NewString(),
					Timestamp: ts,
					DBSystem:  db,
					QueryType: "SKIP",
					RawQuery:  &raw,
				}
				if err := enc.Encode(skipEvt); err != nil {
					log.Errorw("encode skip event", "err", err.Error())
					return err
				}
				continue
			}

			// Fatal parse error
			ts := time.Now().UTC().Format(time.RFC3339Nano)
			raw := line
			errEvt := &parsers.Event{
				EventID:   uuid.NewString(),
				Timestamp: ts,
				DBSystem:  db,
				QueryType: "PARSE_ERROR",
				RawQuery:  &raw,
			}
			_ = enc.Encode(errEvt)
			return fmt.Errorf("parse error: %w", err)
		}

		if evt == nil {
			// Unexpected nil → emit error event
			ts := time.Now().UTC().Format(time.RFC3339Nano)
			raw := line
			errEvt := &parsers.Event{
				EventID:   uuid.NewString(),
				Timestamp: ts,
				DBSystem:  db,
				QueryType: "PARSE_ERROR",
				RawQuery:  &raw,
			}
			if err := enc.Encode(errEvt); err != nil {
				log.Errorw("encode nil event", "err", err.Error())
				return err
			}
			continue
		}

		if err := enc.Encode(evt); err != nil {
			ts := time.Now().UTC().Format(time.RFC3339Nano)
			raw := line
			errEvt := &parsers.Event{
				EventID:   uuid.NewString(),
				Timestamp: ts,
				DBSystem:  db,
				QueryType: "PARSE_ERROR",
				RawQuery:  &raw,
			}
			_ = enc.Encode(errEvt)
			log.Errorw("encode event", "err", err.Error())
			return err
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scan input: %w", err)
	}
	return nil
}
