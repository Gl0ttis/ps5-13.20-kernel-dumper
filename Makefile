# Builds the console-side payloads against the ps5-payload-sdk:
#   ps5-kernel-probe.elf   — binary-searches the data segment end
#   ps5-kernel-dumper.elf  — streams kernel pages to the host receiver
#
# Required: PS5_PAYLOAD_SDK=/path/to/ps5-payload-sdk
#
# Step 1 — probe:
#   make probe PS5_PAYLOAD_SDK=... RECEIVER_HOST=<HOST-IP>
#
# If a prior probe crashed mid-search, pass RESUME_LO to continue:
#   make probe PS5_PAYLOAD_SDK=... RECEIVER_HOST=... RESUME_LO=0x5000000
#
# Step 2 — dump (after layout.json exists):
#   make PS5_PAYLOAD_SDK=... RECEIVER_HOST=... RECEIVER_PORT=8888

ifdef PS5_PAYLOAD_SDK
    include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk
else
    $(error PS5_PAYLOAD_SDK is undefined)
endif

PYTHON        ?= python3
RECEIVER_HOST ?= 127.0.0.1
RECEIVER_PORT ?= 8888
PROBE_PORT    ?= 8889
RESUME_LO     ?= 0
STEP_SIZE     ?= 0x1000000
PROBE_HIGH    ?= 0x8000000

CFLAGS := -Wall -Werror -O2 -g

PS5_HOST ?= ps5
PS5_PORT ?= 9021

PROBE_ELF  := ps5-kernel-probe.elf
DUMPER_ELF := ps5-kernel-dumper.elf

all: $(DUMPER_ELF)

probe: $(PROBE_ELF)

deploy-probe: $(PROBE_ELF)
	$(PS5_DEPLOY) -h $(PS5_HOST) -p $(PS5_PORT) $(PROBE_ELF)

deploy: $(DUMPER_ELF)
	$(PS5_DEPLOY) -h $(PS5_HOST) -p $(PS5_PORT) $(DUMPER_ELF)

$(PROBE_ELF): src/probe.c
	$(CC) $(CFLAGS) \
	    -DRECEIVER_HOST=\"$(RECEIVER_HOST)\" \
	    -DRECEIVER_PORT=$(PROBE_PORT) \
	    -DRESUME_LO=$(RESUME_LO) \
	    -DSTEP_SIZE=$(STEP_SIZE) \
	    -DPROBE_HIGH=$(PROBE_HIGH) \
	    -o $@ $<

layout.h: layout.json scripts/layout-to-header.py scripts/receiver.py
	$(PYTHON) scripts/layout-to-header.py --layout $< --output $@

RESUME_FROM ?= 0
$(DUMPER_ELF): src/dumper.c src/sha256.c src/sha256.h layout.h
	$(CC) $(CFLAGS) \
	    -DRECEIVER_HOST=\"$(RECEIVER_HOST)\" \
	    -DRECEIVER_PORT=$(RECEIVER_PORT) \
	    -DRESUME_FROM=$(RESUME_FROM) \
	    -o $@ src/dumper.c src/sha256.c

clean:
	rm -f $(PROBE_ELF) $(DUMPER_ELF) layout.h

test:
	$(PYTHON) -m unittest discover -s tests -v

.PHONY: all probe deploy deploy-probe clean test
