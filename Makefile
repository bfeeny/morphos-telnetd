# morphos-telnetd
#
# Cross-compiled on the host; runs only on MorphOS.
# Toolchain: ppc-morphos-gcc 15.2.0 from NetBSD pkgsrc (cross/ppc-morphos-gcc).
#
# -noixemul: this is dos.library work, so it must be a libnix binary.
# See doc/ARCHITECTURE.md for why ixemul was rejected.

CROSS  ?= $(HOME)/pkg/gg/bin/ppc-morphos-gcc
SDK    ?= $(HOME)/Documents/MorphOS/morphossdk/Development

CFLAGS  = -noixemul -O2 -Wall -Wextra -Wno-unused-parameter \
          -I$(SDK)/gg/os-include
LDFLAGS =

SRC     = src/telnetd.c src/console_handler.c src/telnet.c src/auth.c
TARGET  = telnetd

all: $(TARGET)

$(TARGET): $(SRC) src/console_handler.h src/telnet.h
	$(CROSS) $(CFLAGS) -o $@ $(SRC) $(LDFLAGS)
	@echo "--- built: $$(file $@) ---"

# Host-side unit tests. These never run on MorphOS; see tests/run.sh.
test:
	@sh tests/run.sh

probe:
	@$(MAKE) -C probe

clean:
	rm -f $(TARGET)
	@$(MAKE) -C probe clean

.PHONY: all test probe clean
