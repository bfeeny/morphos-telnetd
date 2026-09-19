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
	rm -rf telnetd-*.lha telnetd-[0-9]*
	@$(MAKE) -C probe clean

# The release artifact.
#
# An .lha with the binary and the docs, which is the idiomatic level for a
# single-binary daemon on this platform -- an Installer script would be
# gold-plating for something that is one Copy command. Source stays in the
# repo; this is what somebody downloads who does not want a cross-toolchain,
# and most MorphOS users will not stand one up to get a telnetd.
#
# The binary is NOT stripped, deliberately: LogTool can symbolicate a crash
# dump against an unstripped binary and cannot against a stripped one, and
# after a crash that is the only chance anyone gets.
VERSION ?= 1.0
DISTDIR  = telnetd-$(VERSION)

dist: $(TARGET)
	@rm -rf $(DISTDIR) $(DISTDIR).lha $(DISTDIR).tar.gz
	mkdir -p $(DISTDIR)/doc $(DISTDIR)/tools
	cp $(TARGET) $(DISTDIR)/
	cp README.md LICENSE $(DISTDIR)/
	cp doc/*.md $(DISTDIR)/doc/
	cp tools/mkpw.c $(DISTDIR)/tools/
	@# Lhasa -- the lha usually found on Linux and macOS -- can only EXTRACT.
	@# Pack on a MorphOS machine with C:LhA, or anywhere with a real archiver;
	@# otherwise leave a .tar.gz, which is honest rather than a broken .lha.
	@if lha a $(DISTDIR).lha $(DISTDIR) >/dev/null 2>&1 && [ -f $(DISTDIR).lha ]; then \
		echo "--- packed $(DISTDIR).lha ---"; \
	else \
		tar czf $(DISTDIR).tar.gz $(DISTDIR); \
		echo "--- no archiver that can CREATE .lha; wrote $(DISTDIR).tar.gz ---"; \
		echo "    On MorphOS:  LhA a $(DISTDIR).lha $(DISTDIR)"; \
	fi
	@ls -l $(DISTDIR).lha $(DISTDIR).tar.gz 2>/dev/null || true
	@rm -rf $(DISTDIR)

.PHONY: all test probe clean dist
