# morphos-telnetd — a telnet daemon for MorphOS

*Guide for any Claude Code session working in this repo.*

> **Repo status: PRIVATE for now.** It becomes public after testing and discussion with the MorphOS core team. Write everything here as if it were already public — the split below assumes it.

## What we're building
A **telnet daemon for MorphOS** — ported or written — giving the platform a remote interactive shell it currently lacks.

## Why this matters more than it sounds
**MorphOS ships OpenSSH as a client only. There is no `sshd`.** That gap shapes every MorphOS project here: binaries have to be launched by hand on the target and results reported back, because nothing can drive the machine remotely. A working remote shell converts a manual, human-in-the-loop cycle into an automatable one.

**The payoff is bigger than telnet.** The hard parts of `sshd` are the *same* as telnetd's — sockets, spawning a shell, attaching it to a stream, auth — **plus** crypto. `openssl4.library` already ships in the SDK, and OpenSSH's client half is already ported. So **telnetd is the cheap way to prove the plumbing**, and whatever solves it here is exactly what an `sshd` port needs next.

Frame it that way when discussing it with the MorphOS team: not "a plaintext protocol from 1983", but *"the remote-shell plumbing MorphOS is missing, with telnetd as the first consumer and sshd as the intended second."*

## The actual hard part: there are no Unix ptys
> **This is the whole problem. Everything else is routine socket code.**
> A telnetd spawns a shell and wires its stdin/stdout to a socket. On Unix that's a pseudo-terminal. **The Amiga/MorphOS lineage has no ptys** — it has the console handler (`CON:`), `PIPE:`, and custom DOS handlers.
>
> **How do you attach a spawned MorphOS Shell's input and output to a socket?** Candidates:
> 1. **A custom DOS handler** presenting a console-like device backed by the socket — the idiomatic Amiga answer, and almost certainly what AmiTCP did. Most work, best result.
> 2. **`PIPE:` in both directions** around a spawned Shell — simpler, likely loses interactive semantics (raw mode, ^C, line discipline).
> 3. **ixemul's pty support, if it exists** — see below.
>
> **Settle this before choosing a codebase.** It decides whether you're porting a telnetd or writing a DOS handler with a telnet front end.

## The ixemul opportunity
The sibling project (an agentic coding tool) is forced onto **libnix**, because `openssl4.library` requires `-noixemul` and libnix's libc has **no `termios`, no `select`, no `fork`**.

**telnetd needs no TLS, so that constraint doesn't apply here.** It can link **ixemul**, whose libc *does* provide `fork`, `select`, `termios` and `setsid` — much closer to what a BSD telnetd port expects.

- **Check whether ixemul also provides ptys / `openpty`.** If it does, a straight port becomes the obvious path and this project gets dramatically easier.
- **The catch:** `SDK.readme` warns ixemul code away from os-include, `dos.library` and `intuition.library`. If the pty answer turns out to be *a custom DOS handler*, that pulls in `dos.library` and the ixemul route may not survive. **Resolve the pty and ixemul questions together — they are one decision.**

## Prior art — look before writing
- **AmiTCP's telnetd.** AmiTCP 3.x source was released; 4.x went commercial. **Establish which had telnetd, and whether that source is obtainable and usably licensed.** Its value is the Amiga-specific plumbing, not the protocol.
- **BSD / netkit-telnet / GNU inetutils `telnetd`** — portable C, well-understood, likely *easier* to port than resurrecting 1990s Amiga code **if** the pty problem is solved.
- **Check MorphOS Storage, Aminet, OS4 Depot and MorphZone first.** *Standing rule: check what already runs on MorphOS before assuming it doesn't exist.* This has been wrong repeatedly in sibling projects.

## Security posture — decide it, don't inherit it
Telnet is **plaintext**: credentials and session content in the clear. Not a reason to avoid it; a reason to be explicit.

- **Bind narrowly by default** — loopback or the tunnel/LAN interface, never `0.0.0.0`. The primary test machine is a laptop that roams onto café Wi-Fi.
- **Say so plainly in the README** when this goes public: trusted networks or a tunnel only.
- **Auth is an open design question.** MorphOS is single-user with no `/etc/passwd` equivalent. A configured credential? None, relying on network placement? Decide deliberately — it is not a detail.

## Scope
1. **Minimum viable** — listen, accept, spawn a Shell, pass bytes both ways, clean disconnect.
2. **Usable** — option negotiation (echo, suppress-go-ahead, window size `NAWS`), sane terminal behaviour, multiple sessions.
3. **Good citizen** — configurable bind address and port, logging, connection limits, an idiomatic way to start it.

**Get `NAWS` right.** The MorphOS console is xterm-class (`TERM=morphos`, 256 colours, absolute cursor addressing, alternate screen), so a properly negotiated session is genuinely pleasant — and makes full-screen tools usable over the network.

## The target platform
32-bit **big-endian PowerPC**, AmigaOS-lineage API, **no memory protection**, and **SMP does not work** (design single-threaded). The SDK is modern: **GCC 15.2.0**, binutils 2.45.1, cmake, autotools. `time_t`/`off_t` went 64-bit in the May 2026 SDK — **prebuilt binaries older than that are ABI-incompatible; build from source.**

Sockets are **`bsdsocket.library`**. Two shells exist and differ: the MorphOS Shell is not POSIX (no `VAR=value cmd` prefix; **single quotes are not string delimiters — use double quotes**), and the SDK also ships pdksh as `sh`.

## Development loop
**C, cross-compiled on the host; run on real hardware.** Toolchain from **NetBSD pkgsrc** — `cross/ppc-morphos-binutils`, `cross/ppc-morphos-gcc` (GCC 15.2.0, installs under `$PREFIX/gg`), `cross/ppc-morphos-sdk` (**RESTRICTED** distfile — fetch from morphos-team.net, no redistribution). macOS is a supported build host.

**You cannot execute the artifact locally.** Compile errors are yours; runtime behavior is not. **Never claim something "works" when all you did was compile it** — say what was built, what was verified, and what is still unobserved.

**There is a bootstrap irony to plan around:** this project exists to remove the no-`sshd` constraint, but it has to be developed *under* that constraint. Until it works, the user launches it and reports back.

## Code conventions
- **C against the MorphOS SDK.** GCC 15.2.0, so C23 is available.
- **Check every allocation, free what you allocate.** No memory protection — a leak or overrun is a system-level fault.
- **Validate everything off the network.** This is a daemon accepting untrusted input on a machine with no process isolation. Bounds-check the protocol parser; telnet option negotiation is a classic source of overflows.
- **Small, reviewable commits** with real messages — this is meant to be read by MorphOS community contributors who have none of this context.
- **Record provenance.** When you write down a platform fact, note its source: SDK autodoc, forum post, hardware observation, or inference.

## Working norms
- **Research before building.** The failure mode is writing a telnetd around a pty model the platform doesn't have.
- **Say when you're guessing.** Treat platform specifics here as leads, not facts, and correct them as you learn.
- **Prefer the platform's conventions** over forcing Unix patterns onto it. MorphOS developers will notice.

@.claude/CLAUDE.local.md
