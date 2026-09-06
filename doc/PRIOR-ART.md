# Prior art

Standing rule for this project: **check what already runs before assuming it
does not exist.** This is what the search found.

## Existing telnet daemons

| Package | Year | Licence | Source | Notes |
| --- | --- | --- | --- | --- |
| `telnetd 2.0` — Aminet `comm/tcp/telnetd2_0.lha` | 1995 | **GPL** | yes | Peter Simons & Steve Holland. m68k, SAS/C. **The reference design.** |
| `MuFS_Telnetd` — Aminet `comm/tcp/` | 1995 | **GPL** | yes | Andrea Rafreider. Derivative of the above; auth via `multiuser.library`. |
| `ttyhandler` — Aminet `comm/tcp/ttyhandler.lha` | 1996 | freeware | **no** | Kari Melkko. Presents sessions as a `TTY:` device, launched from `inetd.conf`, starts a Shell from `S:Remote-Startup`. Supports telnet LINEMODE. |
| `tnserv` | — | — | not retrieved | Named in the AmiTCP FAQ. "Active daemon", does not use the AmiTCP passwd file. |

**AmiTCP itself does not appear to have shipped a telnetd.** Its FAQ points
users at the third-party daemons above. An early assumption of this project was
that AmiTCP's telnetd was the thing to find; that was wrong.

Nothing telnet-shaped was found on MorphOS Storage or OS4 Depot. MorphOS has
shipped a **VNC server since 3.6**, which is genuine remote access but a GUI —
no use for headless automation or for capturing a driver crash, so the gap this
project addresses is real.

## What telnetd 2.0 contributes

Its value is not the protocol. It is the demonstration, in working code, that a
telnet session can drive a native Shell **by impersonating a console handler**:

- `telnetd.c:331-336` — fabricate a `FileHandle`, point `fh_Type` at the
  process's own `pr_MsgPort`.
- `telnetd.c:1581` — spawn the Shell with `NP_ConsoleTask` set to that port.
- `telnetd.c:504-622` — the packet service loop: `ACTION_READ`, `WRITE`,
  `WAIT_CHAR`, `SCREEN_MODE`, `FIND*`, `END`, `SEEK`, `DISKINFO`.

It also ships a second mechanism, `fakesr.device` — a fake `serial.device`
backed by the socket, for driving getty-style programs (`AxShell`, `uucico`)
that expect a serial line. It is the worse half: more moving parts, needs a
getty, and includes m68k assembly. Not used here.

## Why this project does not port it

The mechanism is reused. **The code is not**, for reasons that are practical
before they are legal:

- **Entry point.** It builds `NOSTARTUP` with `int __asm main(register __a0
  char *, register __d0 long)` — an m68k register-argument entry. Meaningless
  on PowerPC.
- **`SysBase` is read from absolute address 4** (`telnetd.c:173`) — legal, but
  it comes bundled with the m68k assumptions around it. *(An earlier draft of
  this file called that read invalid on MorphOS. It is not: the SDK's own
  `Examples/Misc/procmessages.c` does exactly the same thing. Corrected.)*
- **SAS/C throughout** — `SCOPTIONS` with `PARAMETERS=REGISTERS`, `smakefile`
  driving `sc` and `slink`, `__asm`/`register __aN` declarations.
- **Auth is AmiTCP's**, via `usergroup.library` and a DES `passwd` file. Neither
  exists on MorphOS, so the whole login path is replaced regardless.
- **AmiTCP headers** — `<inetd.h>`, `<amitcp/socketbasetags.h>`, `netinclude:`.
- **The telnet layer is thin and admittedly buggy.** It negotiates `ECHO` and
  `LINEMODE` from two hardcoded strings and **implements no `NAWS` at all** —
  which is one of our explicit requirements. The author's own guide documents
  VT emulation problems and says it "doesn't emulate or interpret a lot".

Of 1590 lines, the part worth having is the ~150-line packet loop, and its
logic is a direct expression of a **documented public API** — the AmigaDOS
packet protocol in `dos/dosextens.h` and `dos.doc`. Reimplementing that from
the SDK headers is both cleaner and less work than porting SAS/C 68k code
around it.

## Licence position

telnetd 2.0 and MuFS_Telnetd are GPL. **This project is MIT**, which is only
legitimate because no code was copied.

The mechanism — which packets a console handler answers, and that
`NP_ConsoleTask` is how you hand a port to a Shell — is documented public API,
not creative expression, and is described in the AmigaDOS literature
independently of telnetd 2.0. It was implemented here from the MorphOS SDK 3.20
headers and autodocs. telnetd 2.0 is credited as prior art that pointed at the
right API.

MIT was chosen over GPL deliberately: the intended second consumer of the
shell-attach layer is an `sshd`, and the audience is the MorphOS core team, who
should be free to absorb this into the system if they want it. A GPL
implementation would foreclose that for no gain.

## Where the archives are

Kept **outside this repository on purpose** (GPL, and not ours to redistribute):

```
~/Documents/MorphOS/prior-art/
  telnetd-2.0-source/   read for mechanism, do not copy
  ttyhandler/           binary + doc only

curl -O https://aminet.net/comm/tcp/telnetd2_0.lha
curl -O https://aminet.net/comm/tcp/ttyhandler.lha
```

## Deployment precedent worth keeping

`ttyhandler` was launched from `inetd.conf` and started its Shell from
`S:Remote-Startup`.

**Verified on MorphOS 3.20 hardware: the configuration ships, the daemon does
not.** `ENVARC:sys/net/inetd.conf` exists with *every* entry commented out, and
`ENVARC:sys/net/services` already defines `telnet 23/tcp`. No `inetd` binary in
`C:`, `MOSSYS:C` or on the path. The disabled entries point at
`NetWork:serv/ftpd` and `NetWork:samba/bin/smbd`, so **`NetWork:serv/`** is
where a daemon is expected to live.

That is a useful thing to be able to tell the MorphOS team: the socket
super-server plumbing is already in place with nothing plugged into it, and the
slot this daemon would occupy is pre-cut.
