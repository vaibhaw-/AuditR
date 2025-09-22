BIN_DIR := bin
LOADR := $(BIN_DIR)/loadr
AUDITR := $(BIN_DIR)/auditr

.PHONY: all loadr auditr clean test

all: loadr auditr test
	@echo "Build complete."

loadr:
	go build -o $(LOADR) ./cmd/loadr

auditr:
	go build -o $(AUDITR) ./cmd/auditr

test:
	go test ./...

clean:
	rm -rf $(BIN_DIR)
