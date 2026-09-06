# Architecture

## The problem

A telnet daemon spawns a shell and wires its stdin/stdout to a socket. On Unix
that is a pseudo-terminal. **The Amiga/MorphOS lineage has no ptys.**

Everything else in a telnetd is routine socket code. This one question decides
the whole design, so it is settled first.

## The answer: be the console handler

On AmigaDOS, a "console" is not a device node — it is **a message port that
answers packets**. A program calling `Read()` on its console does not touch
hardware; `dos.library` turns the call into an `ACTION_READ` packet and sends
it to whatever port that file handle names. Nothing requires the port to belong
to the system console handler.

So: **we point it at ourselves.**

```
+-------------------+     accept()      +---------------------------+
|  listener / inetd | ----------------> |  telnet protocol front    |
+-------------------+                   |  RFC 854 + options        |   replaceable
                                        +------------+--------------+
                                                     |  byte stream, window size,
                                                     |  raw/cooked requests
                                        +------------v--------------+
                                        |  SHELL-ATTACH LAYER       |
                                        |  a MsgPort answering      |   the asset
                                        |  ACTION_READ / WRITE /    |
                                        |  WAIT_CHAR / SCREEN_MODE  |
                                        +------------+--------------+
                                                     |  NP_ConsoleTask
                                        +------------v--------------+
                                        |  CreateNewProc() -> Shell |
                                        +---------------------------+
```

Concretely:

1. `CreateMsgPort()`.
2. `AllocDosObject(DOS_FILEHANDLE, ...)`, set `fh_Type` to that port and
   `fh_Interactive` to `DOSTRUE`.
3. Start a Shell with those handles and `NP_ConsoleTask` set to the same port.
4. Answer the packets it sends.

The packets that matter, and their Unix equivalents:

| AmigaDOS packet | Unix equivalent |
| --- | --- |
| `ACTION_READ` / `ACTION_WRITE` | `read()` / `write()` on the pty |
| `ACTION_WAIT_CHAR` | `select()` — blocking wait with a timeout |
| `ACTION_SCREEN_MODE` | the line discipline: raw vs. cooked (`ICANON`) |
| `ACTION_FINDINPUT` / `FINDOUTPUT` / `FINDUPDATE` | `open()` of the terminal |
| `ACTION_END` | `close()` |

That set *is* a pty, expressed in packets rather than file descriptors.

## Why the shell-attach layer is a separate module

The hard parts of an `sshd` are the same as a telnetd's — accept a connection,
spawn a shell, attach it to a stream, authenticate — **plus** crypto, and
`openssl4.library` already ships in the MorphOS SDK.

So the protocol front end is the disposable half. Keeping shell-attach behind
its own interface means an `sshd` swaps the top box and inherits the rest. That
is the strategic reason this project is worth doing at all, and it is why the
layering above is a requirement rather than a preference.

## Why libnix, not ixemul

MorphOS's ixemul provides `fork`, `select`, `termios` and `setsid` — much
closer to what a BSD telnetd port expects. It was seriously considered, and
rejected for two independent reasons.

**1. ixemul has no pty API.** Not a guess — the SDK contains the output of a
real `configure` run against this platform. `gg/include/python3.14/pyconfig.h`
has `HAVE_OPENPTY`, `HAVE_FORKPTY`, `HAVE_POSIX_OPENPT`, `HAVE_GRANTPT`,
`HAVE_PTSNAME`, `HAVE_UNLOCKPT`, `HAVE_DEV_PTMX` and `HAVE_DEV_PTC` **all
undefined**. There is no `util.h` and no `libutil`, and none of the 870 entries
in ixemul's syscall table is a pty call. The BSD tty headers that are present
(`sys/tty.h`, `ttydev.h`, …) are inherited stubs.

**2. It would not help if it did.** The thing we must attach is a **native
MorphOS Shell** — a `dos.library` program that speaks packets, not a Unix
process that speaks file descriptors. ixemul's process machinery gives Unix
semantics *between ixemul binaries*; it has no way to hand `NP_ConsoleTask` to
`C:Shell`.

So the real question was never "ixemul or libnix" but "is shell-attach
Unix-shaped or DOS-shaped". It is DOS-shaped, which means `dos.library`, and
`SDK.readme` is explicit that ixemul code must not use `dos.library`.

Consequences we accept: no `fork`, no `select`, no `termios` from libc. We do
not need them. `WaitSelect()` from `bsdsocket.library` plus `Wait()` on the
message port is the whole event loop. As a bonus this keeps the libnix-only
`openssl4.library` available for the eventual `sshd`.

## Platform constraints that shape the code

- **No memory protection.** A stray write takes down the machine, not a
  process. Check every allocation; never free something another process may
  still hold; prefer a leak to a double free.
- **SMP does not work.** Design single-threaded.
- **32-bit big-endian PowerPC**, `time_t`/`off_t` 64-bit since the May 2026
  SDK. Build from source; older prebuilt binaries are ABI-incompatible.
- **Untrusted input from the network** on a machine with no process isolation.
  The option-negotiation parser is the classic overflow site — bounds-check it.

## Status

The shell-attach mechanism is **designed and compiled, not yet observed
running.** `probe/conprobe.c` exists to confirm it on real hardware before any
of the daemon is written. See `probe/README.md`.
