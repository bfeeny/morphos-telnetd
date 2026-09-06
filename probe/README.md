# conprobe — does the fake console handler actually work?

A single-purpose probe. It answers the one question that decides the
architecture of this project, and nothing else:

> Can we spawn a native MorphOS Shell whose console is a `MsgPort` we own, and
> drive it entirely by answering AmigaDOS packets?

**There are no sockets in this program.** Input is a canned script compiled into
the binary; output goes to the probe's own stdout. That is deliberate: it
isolates the one thing that cannot be tested from the build host. If the Shell
runs the script, the mechanism is confirmed and the rest of the daemon is
protocol plumbing on top of it. If it does not, we would have found out after
writing a telnetd around a model the platform does not support — which is the
failure this probe exists to prevent.

See `doc/ARCHITECTURE.md` for the mechanism and why it is shaped this way.

## Build

```sh
cd probe
make
```

Needs `ppc-morphos-gcc` (15.2.0, NetBSD pkgsrc `cross/ppc-morphos-gcc`) and the
MorphOS SDK. Override the paths if yours differ:

```sh
make CROSS=/path/to/ppc-morphos-gcc SDK=/path/to/morphossdk/Development
```

## Run

Copy `conprobe` to the MorphOS machine and run it **from a Shell**, not by
double-clicking — it writes its report to stdout.

```
conprobe
```

## What to send back

The complete output. Specifically:

1. **Did the Shell start?** Anything after `spawning Shell with NP_ConsoleTask`.
2. **Did `version` and the two `echo` lines appear?** That is the Shell reading
   our `ACTION_READ` replies and writing back through `ACTION_WRITE` — the
   mechanism working end to end.
3. **Every `[pkt]` line.** These are the payload of the experiment. We do not
   know exactly which packets a MorphOS Shell sends, or in what order, and each
   `UNHANDLED dp_Type = N` is something the real daemon will have to answer.
4. **The `ACTION_SCREEN_MODE raw=` lines**, if any. That is the line discipline
   being set — it is what makes proper echo handling possible over telnet.
5. **The final `RESULT` line.**

## If it misbehaves

- **CTRL-C** is honoured. It does not kill the probe outright; it feeds EOF to
  the Shell and waits for it to exit, because the Shell holds file handles that
  point into our memory and this machine has no memory protection. Yanking them
  away would be a good way to crash it.
- If it hangs with no output at all, the Shell probably never started —
  interesting in itself, please report it.
- There is a hard cap of 20000 packets, after which it drains and exits.

## Expected outcomes

| What you see | What it means |
| --- | --- |
| Script output, `RESULT -- ... CONFIRMED` | The mechanism works. Proceed to build the shell-attach module for real. |
| Shell starts, no output, no packets | `NP_ConsoleTask` did not take. Likely `SYS_FilterTags` — investigate. |
| `SystemTagList() could not start the Shell` | Wrong tags or the Shell needs something we did not provide. `IoErr()` is printed. |
| Lots of `UNHANDLED dp_Type` | Expected and useful — MorphOS's Shell wants more of the console protocol than the 1995 code implemented. |

Nothing here has been observed running. It compiles clean with `-Wall -Wextra`
against the real SDK headers, and that is all that can honestly be claimed
until it runs on hardware.
