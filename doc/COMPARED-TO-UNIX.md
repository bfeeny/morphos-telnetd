# How this differs from a Unix telnetd

*Written for people who know what `telnetd` does on Linux or BSD and want to
know what changes on MorphOS, and why.*

The short version: **almost every structural decision here follows from the
absence of a pseudo-terminal.** A Unix telnetd is mostly glue around facilities
the kernel already provides — a pty, a line discipline, `fork`, `login`. None of
those exist here, so this daemon has to *be* several of them. What is left that
looks like a Unix telnetd is the RFC 854 parser, and that is deliberately the
smallest and most replaceable part of the program.

Reference points used throughout: **BSD/netkit `telnetd`** (the lineage behind
most Linux distributions' `telnetd`), **GNU inetutils `telnetd`**, and
**busybox `telnetd`** (the small one, worth reading because its shortcuts are
instructive).

---

## 1. The pty, and what replaces it

| | Unix | Here |
| --- | --- | --- |
| Attach a shell to a stream | `openpty()` / `forkpty()` | Become the shell's **console handler** |
| The shell's view | a tty device node | a `MsgPort` that answers DOS packets |
| Who does line discipline | the kernel | this program |

On Unix, `telnetd` opens a pty pair, `fork`s, makes the child a session leader,
`dup2`s the slave onto fds 0/1/2 and `exec`s `login`. Everything after that is
copying bytes between the master fd and the socket.

There are no ptys in the Amiga lineage. What there is instead: **an AmigaDOS
console is not a device node, it is a message port that answers packets.** A
program calling `Read()` on its console does not touch hardware — `dos.library`
turns the call into an `ACTION_READ` packet and posts it to whatever port that
file handle names. Nothing requires that port to belong to the system console
handler.

So this daemon points a spawned Shell at a port it owns and answers the packets
itself:

| AmigaDOS packet | Unix equivalent |
| --- | --- |
| `ACTION_READ` / `ACTION_WRITE` | `read()` / `write()` on the pty master |
| `ACTION_WAIT_CHAR` | `select()` on the tty |
| `ACTION_SCREEN_MODE` | `ICANON` — raw vs cooked |
| `ACTION_FINDINPUT` / `FINDOUTPUT` / `FINDUPDATE` | `open()` of the terminal |
| `ACTION_END` | `close()` |
| `ACTION_EXAMINE_FH` | `fstat()` on the tty |
| `ACTION_CHANGE_SIGNAL` | where `SIGINT` should be delivered |

That set *is* a pty, expressed in packets rather than file descriptors. The
consequence worth internalising: **on Unix the kernel is between the shell and
the daemon; here there is nothing in between.** A mistake in packet accounting
does not produce an `EIO`, it hangs a process or takes down the machine.

## 2. One process, not one per connection

BSD `telnetd` is a **process per connection**, usually started by `inetd` with
the socket already on stdin. It forks again for the login shell. Concurrency is
the kernel's problem.

Here there is **one process serving every session**, multiplexed with a single
`WaitSelect()`:

```c
nready = WaitSelect(maxfd + 1, &rd, &wr, NULL, &tv, &sigs);
```

`WaitSelect()` is `bsdsocket.library`'s `select()` **plus an Exec signal mask as
its sixth argument** — so one wait covers the listener, every session's socket,
and every session's console message port at once. That single call is what makes
the design possible.

Why not a process per session:

- **`fork()` does not exist** in libnix, and this must be a libnix build (see
  `ARCHITECTURE.md` — shell-attach is `dos.library` work, which ixemul code is
  told not to do).
- **SMP does not work on MorphOS.** Threads buy nothing.
- Sessions are I/O bound; the entire daemon is idle almost all the time.

The cost is that any blocking call blocks *everyone*. That is not theoretical:
authentication originally ran in a loop of its own with its own `WaitSelect`,
and while it ran nothing else was serviced — one slow client froze every
established session. The login dialogue is now a state machine driven from the
main loop, which on Unix would be pointless work because `login` runs in its own
process.

## 3. Line discipline is ours

A Unix telnetd barely thinks about newlines: the pty's `ONLCR` turns `\n` into
`\r\n` on the way out, and `ICRNL` handles the way in. Both are kernel flags.

Here there is no kernel doing it, so `telnet.c` does:

- **Outbound**, `\n` becomes `CR LF` and a bare `CR` becomes `CR NUL` (RFC 854
  p.11). Without this, output staircases on any client that has cleared `ONLCR`
  on its own terminal — which BSD `telnet` does as soon as it accepts our
  `WILL ECHO`.
- **Inbound**, `CR LF` becomes one newline and `CR NUL` becomes a bare CR.
  Passing the CR through hands the Shell `version\r`, which it correctly rejects
  as an unknown command.
- **Raw vs cooked** arrives as `ACTION_SCREEN_MODE` (1 = raw, 0 = cooked),
  which is what `ICANON` would be. The name is a misnomer of long standing;
  AmigaOS 4 renamed it `ACTION_SINGLE_CHARACTER_MODE`.

**Echo** is also ours. The daemon sends `WILL ECHO`, so the client does not echo
and we do — which is why hiding a password needs no mode change at all, just a
decision not to echo those bytes.

## 4. Window size: there is no `SIGWINCH`

On Unix, `NAWS` arrives, the daemon calls `ioctl(TIOCSWINSZ)`, and the kernel
sends `SIGWINCH` to the foreground process group. Programs redraw.

**MorphOS has no resize notification** — there is no such packet among the 82
`ACTION_*` constants. A program cannot be told the size changed; it can only
ask. So:

- `NAWS` updates a value we hold (columns first, big-endian, RFC 1073).
- When a program wants the size it writes `CSI SP q` (bytes `9B 20 71` — CSI is
  the single byte `0x9B`, **not** `ESC [`) to its console, i.e. to us.
- We detect that in the *outgoing* stream, swallow it, and queue the answer
  `CSI 1;1;<rows>;<cols> SP r` where the next read will find it.

Answered from the current value **at the moment of asking**, never from one
cached at connect. `ESC [ 6 n` (cursor position) is terminal knowledge and is
forwarded to the client; size is handler knowledge and is answered locally.

## 5. Authentication: there is no `/bin/login`

BSD `telnetd` does not authenticate. It `exec`s `/bin/login` and gets out of the
way — PAM, `utmp`, `lastlog`, password ageing and the rest are somebody else's
code.

MorphOS has no `login` binary to exec, so this daemon authenticates itself,
against **the system's own user database** via `usergroup.library`:
`getpwnam()`, then `crypt()` the typed password with the stored hash as its salt
(the whole stored string is the salt argument — DES reads two characters, MD5
reads `$1$...$`). Accounts come from **Preferences → Users**.

Differences a Unix admin will notice:

- **An account with no password is refused, not admitted.** The out-of-the-box
  MorphOS state is a blank password; failing open would hand a shell to anyone.
- **No `utmp`/`wtmp`/`lastlog`.** `who` will not show telnet sessions.
- **No `/etc/nologin`, no login classes, no PAM.**
- **No `TERM` propagation.** The daemon negotiates `DO TTYPE` but never sends
  the `SB TTYPE SEND` subnegotiation, so it never learns the client's terminal
  type — and `TERM` in the session is whatever the Shell's environment says.
  RFC 1091 permits this (asking is the server's choice), but it is dead
  negotiation and is on the list to either use or drop.

## 6. Option negotiation is simpler than BSD's, deliberately

BSD `telnetd` implements the full **RFC 1143 "Q method"** — per-option state
machines with `WANTYES`/`WANTNO` and queued transitions, which exists to make
negotiation converge when both ends change their minds at once.

This daemon offers exactly four things — `WILL ECHO`, `WILL SGA`, `DO NAWS`,
`DO TTYPE` — refuses everything else with `DONT`/`WONT`, and keeps **no option
state at all**. It cannot loop, because it never sends a request in response to
a response. Agreement with something we offered is answered with silence, which
RFC 854 requires ("acknowledgements must not be sent for a request already in
effect").

**Where that is currently wrong:** `DONT` and `WONT` are not honoured. RFC 854
requires that a request to *disable* always be accepted. A client sending
`DONT ECHO` gets no `WONT` back and we keep echoing; a Q-method client is then
stuck in `WANTNO` waiting for a reply that never comes, and characters double.
This is a real conformance gap, tracked, and not yet fixed.

The parser itself is a **byte-at-a-time state machine** that can be suspended at
any byte, because TCP does not respect message boundaries. busybox's telnetd
peeks at `buf[1]`, `buf[2]`, `buf[3]` instead and carries a literal
`"BUG: incomplete, can't process"` comment about a `NAWS` subnegotiation split
across two reads. That is the bug this design exists to avoid.

## 7. `inetd`, and why we are a standalone listener

Most Unix telnetds are launched by `inetd` with the connection already on
stdin/stdout; the daemon never calls `socket()`, `bind()` or `accept()`.

MorphOS **does** ship `MOSSYS:Net/INetD`, with `ENVARC:sys/net/inetd.conf` and
`services`. But every entry in the shipped `inetd.conf` is disabled, `INetD` is
not running, and its `ftp` line points at `NetWork:serv/ftpd` — **a path that
does not exist**: `Networks:` on 3.20 is the NETBIOS handler and is not
writable. That reference is a vestigial AmiTCP-era default.

So this is a standalone listener with its own accept loop. Running as an inetd
service would be the more idiomatic MorphOS answer and is worth doing later, but
it needs a mode where the socket arrives as stdin, which does not exist yet.

## 8. Resources: nothing is reclaimed at exit

This is the difference that changes the most code, and it has no Unix analogue.

On Unix, a process exit closes every fd, frees every page, and removes every
lock. Sloppiness is bounded by the process lifetime. **On MorphOS nothing is
reclaimed until reboot.** A leaked lock, file handle, DOS device entry or signal
bit is leaked *for good*.

Consequences visible in this code:

- **Message ports are pooled, not freed.** `CreateMsgPort()` consumes one of
  roughly a dozen usable **Exec signal bits**; never reusing them meant the
  daemon refused every caller after about a dozen logins. Freeing a port a Shell
  might still hold is worse than leaking it — that is a dead machine, not an
  error — so ports are recycled and never released.
- **Departing sessions leave a *reaper*.** When a client vanishes the Shell does
  not stop existing; it is told EOF and exits in its own time. Ending the
  session immediately left the Shell writing to a port nobody would read again,
  blocked in `WaitPort` for ever. A reaper keeps answering until it lets go.
- **The log is opened, appended to and closed per line.** Held open, it could
  not be read while the daemon ran (`MODE_NEWFILE` takes an exclusive lock), and
  any exit that skipped the `Close()` locked the file to a dead process until
  reboot — so a failed boot made its own explanation unreadable.
- **Ports nobody will read again are set `PA_IGNORE`** before being abandoned,
  so a surviving Shell cannot `Signal()` a Task that has been freed.

## 9. Signals and `^C`

Unix: the line discipline sees `\x03`, sends `SIGINT` to the foreground process
group, and the daemon is not involved.

Here, `ACTION_CHANGE_SIGNAL` arrives as the **first packet of every session** and
carries the `MsgPort` of the process to signal — `dp_Arg2` is a `MsgPort *`, not
a Task, so the break is
`Signal(port->mp_SigTask, SIGBREAKF_CTRL_C)`. That value is captured and, at time
of writing, **not yet used**: sending `^C` to a running command is not
implemented. It is the most conspicuous missing feature relative to a Unix
telnetd.

## 10. Flow control

A Unix telnetd inherits back-pressure: the pty and the socket both block, and
the shell stops when the pipe fills.

Here it is explicit. Output is queued per session, and once the queue passes a
high-water mark **the session stops taking packets off its console port at
all** — the Shell's next write sits unanswered and it blocks in `WaitPort`,
which is exactly what a full pipe does to a process on Unix. Input is symmetric:
the socket leaves the read set when the input buffer is full, so TCP does the
flow control rather than the daemon parsing bytes it must then discard.

## 11. ixemul programs are a second class of client

Not a Unix distinction at all, but the one most likely to surprise.

Programs built against **ixemul** (MorphOS's BSD compatibility layer — pdksh,
much of the SDK) ask a console for things the MorphOS Shell never does:

- **`ACTION_SESSION_MODE` (991)** — ixemul's *private* packet, defined in its own
  source and in no SDK header. It asks "are you a linux compatible console
  handler?", and it must be answered `DOSTRUE` in **both** result fields.
  Refusing it makes ixemul write `0x84` (the Amiga console's INDEX control)
  instead of a newline as soon as a program clears `ONLCR` — so the failure
  appears only in raw mode, which is the hardest case to notice by hand.
- **`ACTION_EXAMINE_FH`** — `fstat()`. Answered with `ST_PIPEFILE`, which ixemul
  maps to `S_IFCHR`; `ST_FILE` would make us one of the handlers ixemul's source
  complains about, whose "console windows claim they're plain files".
- **`/dev/tty` does not work**, so pdksh reports *"No controlling tty"* and runs
  without job control. Note what this is *not*: `Open("*")` resolves to this
  handler correctly and returns a working interactive handle — measured with
  `probe/starprobe.c`. ixemul does not use `Open()` for `/dev/tty`; it maps the
  name to `"*"` and calls its own `__open()`, and that is where the failure
  lives. Unsolved, and the next step is a packet trace rather than more
  reading.

An interactive `pdksh` over telnet **does** work (`GG:bin/sh` — it is not on the
MorphOS Shell's path), including POSIX arithmetic and exit status.

---

## Summary table

| | BSD/netkit telnetd | This |
| --- | --- | --- |
| Shell attach | pty pair | console handler answering DOS packets |
| Concurrency | process per connection | one process, `WaitSelect` |
| Started by | `inetd`, socket on stdin | own listener; `-d` to detach |
| Line discipline | kernel termios | in `telnet.c` |
| Window size | `TIOCSWINSZ` + `SIGWINCH` | answered on demand, no notification exists |
| Authentication | `exec /bin/login` | `usergroup.library` in-process |
| Option state | RFC 1143 Q method | none; four offers, refuse the rest |
| `^C` | `SIGINT` from the line discipline | **not implemented** |
| `DONT`/`WONT` | honoured | **not honoured** |
| `TERM` | negotiated and exported | negotiated, never asked for |
| Resource cleanup | kernel, at exit | manual, for ever |
| Session accounting | `utmp` / `wtmp` | none |

## What would need to change for `sshd`

The point of the layering. `telnet.c` is the disposable half: an `sshd` deletes
it, keeps `console_handler.c` and the session machinery in `telnetd.c`, and adds
crypto — `openssl4.library` already ships in the SDK. The parts that were hard
here are the parts an `sshd` would otherwise have to solve from scratch:
attaching a real Shell to a byte stream, window size without a pty, and surviving
on a platform that reclaims nothing.
