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

# The release artifact: an .lha for Aminet and MorphOS Storage.
#
# LHA MUST BE AN IMPLEMENTATION THAT CAN *CREATE* ARCHIVES, and the one you
# probably have cannot. `brew install lha` gives you Lhasa, which is
# extract-only; 7-Zip lists Lzh but returns E_NOTIMPL if asked to write one.
#
# Creating implementations exist -- this is a packaging quirk, not a gap in the
# world. LHa for UNIX 1.14i (github.com/jca02266/lha) writes .lha and MacPorts
# ships it as `lha`. Its licence restricts binary redistribution, which is very
# likely why Homebrew and the Linux distributions ship the clean-room
# extract-only Lhasa under the same command name. Built from source here and
# installed as `lha-unix` so it does not shadow Homebrew's.
#
# Override with:  make dist LHA=/path/to/creating/lha
LHA     ?= lha-unix
VERSION ?= 1.0

# NO VERSION IN THE FILENAME, deliberately, and on Aminet's own instruction:
# "Version numbers should be part of the readme file, not part of the
# filename." Uploading again under the SAME name is how Aminet replaces a
# package -- "the preferred way to do updates" -- so a stable name keeps one
# listing, one link, and no trail of superseded versions. It also matters for
# the 30-character limit, of which ".ppc-morphos.lha" already spends sixteen.
PKG      = telnetd.ppc-morphos

# The binary is NOT stripped, deliberately: LogTool can symbolicate a crash
# dump against an unstripped binary and cannot against a stripped one, and
# after a crash that is the only chance anyone gets.
dist: $(TARGET)
	@# A version that has been uploaded is never rebuilt from a newer tree.
	@# See packaging/RELEASED for the reasoning and how to reproduce one.
	@if [ -f packaging/RELEASED ] && grep -q '^$(VERSION)[[:space:]]' packaging/RELEASED; then \
		echo "ERROR: version $(VERSION) is already released."; \
		echo "  Anything changed since then needs a new version number."; \
		echo "  Latest released: $$(grep -v '^#' packaging/RELEASED | awk 'NF{v=$$1} END{print v}')"; \
		echo "  Build with:      make dist VERSION=<next>"; \
		echo "  To reproduce $(VERSION) exactly, check out its commit instead."; \
		exit 1; fi
	@# A release is built from a COMMITTED tree, never a working copy. 1.0 was
	@# built, then README.md was edited, then committed -- so no commit
	@# reproduces the archive that was uploaded. Refusing a dirty tree makes
	@# every future release correspond to exactly one commit.
	@# `git status --porcelain`, not `git diff`: diff ignores UNTRACKED files,
	@# and this target copies src/*.c wholesale -- a stray untracked source
	@# file would ship in the release without ever having been committed.
	@if [ -n "$$(git status --porcelain)" ]; then \
		echo "ERROR: uncommitted changes. Commit first, then build the release,"; \
		echo "  so the package corresponds to exactly one commit:"; \
		git status --short | sed 's/^/    /'; \
		exit 1; fi
	@rm -rf release
	mkdir -p release/telnetd/doc release/telnetd/src release/telnetd/tests release/telnetd/tools
	cp $(TARGET) release/telnetd/
	cp README.md LICENSE Makefile release/telnetd/
	cp doc/*.md release/telnetd/doc/
	@# Source ships too, and not as a courtesy: the LICENSE in this archive
	@# grants rights to source, so an archive without it is an MIT licence
	@# over something the reader cannot see. It also makes the package
	@# rebuildable on its own rather than only alongside a clone.
	cp src/*.c src/*.h release/telnetd/src/
	cp tests/*.c tests/*.sh tests/*.py release/telnetd/tests/
	cp tools/mkpw.c release/telnetd/tools/
	@find release -name '._*' -o -name '.DS_Store' | xargs rm -f 2>/dev/null || true
	@# Aminet requires the readme to share the archive's base name.
	@# The version is STAMPED in, not typed: the readme is a template with
	@# @VERSION@ where the number goes, so a release is `make dist
	@# VERSION=1.1` and there is no second place to forget to edit.
	sed 's/@VERSION@/$(VERSION)/' packaging/$(PKG).readme > release/$(PKG).readme
	@grep -q '^Version: *$(VERSION)$$' release/$(PKG).readme || { \
		echo "ERROR: the readme did not get Version $(VERSION) stamped in."; \
		echo "  Check packaging/$(PKG).readme still has @VERSION@."; exit 1; }
	@cd release && $(LHA) a $(PKG).lha telnetd >/dev/null 2>&1 || { \
		echo "ERROR: $(LHA) cannot create archives."; \
		echo "  Lhasa (Homebrew's 'lha') and 7-Zip extract only."; \
		echo "  Use MacPorts 'lha', or build github.com/jca02266/lha,"; \
		echo "  or pass LHA=/path/to/one that can."; exit 1; }
	@rm -rf release/telnetd
	@echo
	@echo "--- release/$(PKG).lha ---"
	@$(LHA) l release/$(PKG).lha | tail -n +1
	@echo
	@ls -l release/

.PHONY: all test probe clean dist

