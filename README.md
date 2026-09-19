# morphos-telnetd

A telnet daemon for MorphOS — a remote shell for a platform that has never had
one.

MorphOS ships OpenSSH as a *client only*. There is no `sshd`, no `telnetd`, and
no working `inetd`, so nothing can drive the machine remotely. This fills that
gap, and is built so the harder half can be reused: the part that attaches a
real MorphOS Shell to a byte stream is a standalone module with no networking in
it, because the intended second consumer is an `sshd`.

## Status

**In daily use**, on MorphOS 3.20 (PowerBook G4), as the inbound channel for a
small fleet of machines — including one occasion when it was the only way into a
machine whose other remote channel had wedged, which is what it was built for.

- authenticated login against the system's own user database
- several concurrent sessions
- window size (`NAWS`) carried end to end, so full-screen programs know their
  geometry
- survives idle clients, mid-command disconnects, connect-and-drop, and clients
  that flood without reading
- starts at boot and comes back on its own after a reboot
- an interactive `pdksh` works over it, as well as the MorphOS Shell

What that does **not** mean: it has had no outside security review, and telnet
is a plaintext protocol. Read `doc/SECURITY.md` before putting it on a network
you do not control. Known gaps are listed honestly at the end of
`doc/COMPARED-TO-UNIX.md` rather than left for you to find.

## Requirements

- **MorphOS 3.x.** Developed and used on 3.20.
- **`bsdsocket.library`** and **`usergroup.library`** — both ship with MorphOS;
  nothing to install.
- **A configured, running network stack.** The daemon refuses to start if it
  cannot open `usergroup.library`, because it would have no way to check a
  password.
- **An account with a password set**, in Preferences → Users. See *Accounts*.

To build it yourself you also need the MorphOS SDK, and either a native
toolchain or the `ppc-morphos-gcc` cross-toolchain. To *run* a release build you
need neither.

## Install

`telnetd` is a single binary with no support files.

```
Copy telnetd TO C:
Protect C:telnetd +e
```

`C:` puts it on the command path, which is what the examples below assume. Any
directory works if you would rather keep it apart — use the full path when you
start it (`Work:telnetd/telnetd`), including in the boot script.

## Run

```
telnetd [-p port] [-b address] [-d] [-t seconds] [-n seconds] [-l logfile]

  -p   port to listen on            (default 23)
  -b   bind to one address          (default: all interfaces)
  -d   detach and run in background (for boot scripts and supervisors)
  -t   seconds to wait for the first connection, 0 = forever
  -n   seconds to wait for the network stack (for boot scripts)
  -l   write diagnostics to a file
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

The log can be read while the daemon is running — it is opened and closed per
line, so `Type Work:telnetd.log` works on a live daemon.

## Starting it at boot

**Put it in `S:user-network-startup`, not `S:User-Startup`.** This matters more
than it looks, and it is the one instruction in this README that was paid for in
reboots.

```
;BEGIN TELNETD
FailAt 100
If Exists C:telnetd
  C:telnetd -d -p 23 -n 60 -l Work:telnetd.log
EndIf
FailAt 21
;END TELNETD
```

### Why not `S:User-Startup`

`S:startup-sequence` **never calls the network chain.** Networking is started
separately by `MOSSYS:S/network-startup`, whose last act is to execute
`S:user-network-startup` — *after* `netconfig autoconfig`. So `S:User-Startup`
runs at a point where `bsdsocket.library` is loaded but **no interface has an
address yet**.

Measured on one machine, three consecutive boots from `S:User-Startup`:

```
telnetd: bind not ready, errno = 49      <- EADDRNOTAVAIL
telnetd: bound after seconds = 4
```

and from `S:user-network-startup`:

```
telnetd: network wait finished, seconds = 0
telnetd: listening on all interfaces port 23
```

Every boot, not an unlucky fraction. Note that this happens even binding
`INADDR_ANY` — the dependency is on the stack being *configured at all*, not on
any particular address existing, so choosing a bind address does not avoid it.

`-n 60` tells the daemon to retry `bind()` for up to a minute, logging how long
it waited. With the correct hook you should never need it; keep it anyway, as a
belt for a slow or DHCP-dependent setup. It costs nothing when it is not needed,
and it turns any residual delay into a number in the log instead of a mystery.

`FailAt` keeps a failure here from aborting the rest of the boot, and
`If Exists` makes a missing binary a skipped line rather than a fatal one.

## Accounts

Authentication uses the accounts in **MorphOS Preferences → Users**, via
`usergroup.library`. Set a password there before remote login will work: an
account with no password, or one locked with `*`, is refused rather than
admitted — the out-of-the-box state is a blank password, and failing open would
hand a shell to anyone who connects.

**There is no way to disable authentication.** An earlier `-a` flag that skipped
the login has been removed outright rather than defaulted off, so that no build
of this daemon — however configured or compiled — can serve an unauthenticated
shell. Passing `-a` now makes it refuse to start and say why.

`tools/mkpw.c` can add an account directly. By default it writes a test file and
needs an explicit `-live` flag to touch the system database.

## Releases

The release artifact is an **`.lha` containing the binary and these docs** —
the idiomatic level for a single-binary daemon on this platform. There is no
Installer script and there should not be: installation is one `Copy` command,
and an Installer for that would be ceremony.

Source lives in this repository for anyone who wants to build or audit it; the
`.lha` exists so that getting a telnetd does not require standing up a
cross-toolchain first.

`make dist` stages the tree. Note that the `lha` usually found on Linux and
macOS is **Lhasa, which can only extract** — pack the final archive on a
MorphOS machine (`LhA a telnetd-1.0.lha telnetd-1.0`) or with any archiver that
can actually create the format. `make dist` falls back to a `.tar.gz` and tells
you, rather than pretending.

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

Do not strip the binary. An unstripped one can be symbolicated by `LogTool`
against a crash dump; a stripped one cannot, and that is the only chance you get
after the fact.

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
telnetd does** — what changes without a pty, why almost every structural
decision here follows from that, and a candid list of what it does not do.
`doc/PRIOR-ART.md` records what was surveyed first. `doc/SECURITY.md` is honest
about what telnet does and does not protect.

## Licence

MIT. This is a clean implementation against the MorphOS SDK headers and
autodocs; no GPL code was copied. See `doc/PRIOR-ART.md`.
