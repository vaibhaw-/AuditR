BIN_DIR := bin
LOADR := $(BIN_DIR)/loadr
AUDITR := $(BIN_DIR)/auditr

.PHONY: all loadr auditr clean

all: loadr auditr

loadr:
	go build -o $(LOADR) ./cmd/loadr

auditr:
	go build -o $(AUDITR) ./cmd/auditr

clean:
	rm -rf $(BIN_DIR)
