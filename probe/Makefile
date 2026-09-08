# conprobe -- MorphOS fake-console-handler probe
#
# Cross-compiled on the host; runs only on MorphOS.
# Toolchain: ppc-morphos-gcc 15.2.0 from NetBSD pkgsrc (cross/ppc-morphos-gcc).

CROSS   ?= $(HOME)/pkg/gg/bin/ppc-morphos-gcc
SDK     ?= $(HOME)/Documents/MorphOS/morphossdk/Development

# -noixemul: this is dos.library work, so it must be a libnix binary.
# See doc/ARCHITECTURE.md for why ixemul was rejected.
CFLAGS  = -noixemul -O2 -Wall -Wextra -Wno-unused-parameter \
          -I$(SDK)/gg/os-include

TARGET  = conprobe
EXTRA   = starprobe

all: $(TARGET) $(EXTRA)

$(TARGET): conprobe.c ../src/console_handler.c ../src/console_handler.h
	$(CROSS) $(CFLAGS) -o $@ conprobe.c ../src/console_handler.c
	@echo "--- built: $$(file $@) ---"

clean:
	rm -f $(TARGET) $(EXTRA)

.PHONY: all clean

starprobe: starprobe.c
	$(CROSS) $(CFLAGS) -o $@ starprobe.c
	@echo "--- built: $$(file $@) ---"
