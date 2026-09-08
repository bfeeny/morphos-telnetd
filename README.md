# morphos-telnetd

A telnet daemon for MorphOS — a remote shell for a platform that has never had
one.

MorphOS ships OpenSSH as a *client only*. There is no `sshd`, no `telnetd`, and
no `inetd`, so nothing can drive the machine remotely. This fills that gap, and
is built so the harder half can be reused: the part that attaches a real MorphOS
Shell to a byte stream is a standalone module with no networking in it, because
the intended second consumer is an `sshd`.

## Status

Working, and not yet battle-tested. Verified on MorphOS 3.20 (PowerBook G4):

- authenticated login against the system's own user database
- several concurrent sessions
- window size (`NAWS`) carried end to end, so full-screen programs know their
  geometry
- survives idle clients, mid-command disconnects, and connect-and-drop
- runs detached, so it can be started at boot

## Build

Cross-compiled on a host with `ppc-morphos-gcc` (NetBSD pkgsrc
`cross/ppc-morphos-gcc`, GCC 15.2.0) and the MorphOS SDK:

```sh
make                 # builds telnetd
make test            # host-side unit tests -- these never run on MorphOS
```

`make test` builds for the *build host* and refuses to run on MorphOS. The logic
it covers decides when it is safe to stop servicing a live Shell's packets, and
getting that wrong on a machine with no memory protection takes down the OS — so
it is exercised where a mistake costs nothing.

## Run

```
telnetd [-p port] [-b address] [-d] [-t seconds] [-l logfile] [-a]

  -p   port to listen on            (default 23)
  -b   bind to one address          (default: all interfaces)
  -d   detach and run in background (for boot scripts and supervisors)
  -t   seconds to wait for the first connection, 0 = forever
  -n   seconds to wait for the network stack (for boot scripts)
  -l   write diagnostics to a file
  -a   DISABLE AUTHENTICATION -- development only, see SECURITY.md
```

Typical supervised start:

```
telnetd -d -p 23 -l Work:telnetd.log
```

> [!note] Use `-d`, not the shell
> `Run` is an AmigaDOS command that pdksh does not resolve — the line silently
> does nothing. Backgrounding with the shell's `&` starts a process that never
> binds, because `usergroup.library` does not get a usable context. `-d`
> re-launches the binary as its own program, which works from any launcher.
>
> **Check the port, not the process.** A resident `telnetd` in `Status` does not
> mean a listening one.

## Accounts

Authentication uses the accounts in **MorphOS Preferences → Users**, via
`usergroup.library`. Set a password there before remote login will work: an
account with no password, or one locked with `*`, is refused rather than
admitted — the out-of-the-box state is a blank password, and failing open would
hand a shell to anyone who connects.

`tools/mkpw.c` can add an account directly. By default it writes a test file and
needs an explicit `-live` flag to touch the system database.

## How it works

A telnet daemon spawns a shell and wires it to a socket. On Unix that is a
pseudo-terminal — and **the Amiga lineage has no ptys**. The answer is that an
AmigaDOS console is not a device node but *a message port that answers packets*,
so this daemon points a spawned Shell at a port it owns and answers those
packets itself. `ACTION_WAIT_CHAR` is `select()`; `ACTION_SCREEN_MODE` is the
line discipline.

`doc/ARCHITECTURE.md` has the detail, including why this is a libnix build and
why the shell-attach layer is deliberately separable.
**`doc/COMPARED-TO-UNIX.md` is the one to read if you already know what a Unix
telnetd does** — what changes without a pty, and why almost every structural
decision here follows from that. `doc/PRIOR-ART.md` records what was surveyed
first. `doc/SECURITY.md` is honest about what telnet does and does not
protect.

## Licence

MIT. This is a clean implementation against the MorphOS SDK headers and
autodocs; no GPL code was copied. See `doc/PRIOR-ART.md`.
