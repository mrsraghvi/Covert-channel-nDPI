NDPI_DIR   := nDPI-dev
NDPI_LIB   := $(NDPI_DIR)/src/lib/libndpi.a
NDPI_INC   := $(NDPI_DIR)/src/include

CC      := gcc
CFLAGS  := -O2 -Wall -Wextra -I$(NDPI_INC) -D_GNU_SOURCE
LDFLAGS := $(NDPI_LIB) -lpcap -lm -lpthread -ldl

TARGET  := covert_detector
SRC     := covert_channel_detector.c

.PHONY: all ndpi clean

all: $(TARGET)

# Clones (if needed) and builds nDPI. Not vendored in this repo (~280MB
# source tree) — pulled fresh from upstream on first build.
ndpi:
	@if [ ! -d $(NDPI_DIR) ]; then \
		echo "Cloning nDPI ..."; \
		git clone --depth 1 https://github.com/ntop/nDPI.git $(NDPI_DIR); \
	fi
	@if [ ! -f $(NDPI_LIB) ]; then \
		echo "Building nDPI ..."; \
		cd $(NDPI_DIR) && ./autogen.sh && ./configure && $(MAKE) -j$$(nproc); \
	else \
		echo "nDPI already built."; \
	fi

$(TARGET): ndpi $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET) $(LDFLAGS)
	@echo "Built ./$(TARGET). Run with: sudo ./$(TARGET) <iface> [\"bpf filter\"]"

clean:
	rm -f $(TARGET)
