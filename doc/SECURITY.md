# Security

Telnet is a plaintext protocol. This document says exactly what that means here,
what protection this daemon does and does not provide, and why.

## Authentication

A session must authenticate before a Shell is started. Credentials come from
**the system's own user database** — the accounts in MorphOS Preferences →
Users — via `usergroup.library`:

```
getpwnam(name) -> ug_GetSalt(pw, ...) -> crypt(typed, salt) -> compare
```

`pw_passwd` holds a **salted hash**, not a password, so the comparison is
hash-against-hash. Change your password in Preferences and it takes effect here
with nothing to keep in sync.

### An account with no password cannot log in remotely

**This is deliberate and it is the most important rule in the file.** The
out-of-the-box MorphOS state is a blank password. If a blank password admitted
anyone, a fresh install running this daemon would hand a Shell to every host on
the network. So a blank password is a refusal, not a wildcard.

**Set a password in Preferences → Users before remote login will work.**

Every failure — unknown user, no password set, wrong password — returns the
same `Login incorrect.` to the client. The log distinguishes them; the network
does not.

## What this daemon does NOT protect you from

> [!warning] The daemon necessarily sees your password in plaintext
> On Unix, `telnetd` execs `/bin/login` and genuinely cannot observe the
> password, **because the kernel owns the pseudo-terminal** and the daemon sits
> on the far side of a protection boundary.
>
> **That trick cannot work on MorphOS, and it is worth understanding why.** This
> daemon *is* the console handler. Every byte any program reads from the session
> arrives as an `ACTION_READ` that this process answers. Delegating the prompt
> to `MOSSYS:C/Login` would change nothing: its password prompt would read
> *through us*. There is no boundary to hide behind, because we are the
> boundary.
>
> So the honest position is: the plaintext exists in one stack buffer for as
> long as it takes to hash it, and is wiped immediately after. That is a
> reasonable story for a pre-boundary component. It is **not** "the daemon never
> sees your credentials", and this project will not claim that.

Further, and independent of telnet:

- **The password crosses the network in the clear.** Anyone able to observe the
  traffic can read it. This is inherent to telnet and no implementation fixes it.
- **MorphOS has no memory protection.** A user identity is *representable* —
  `usergroup.library` keeps per-process credentials and `getlogin()` reports
  them — but nothing isolates one process's memory from another's. Treat a
  session as **identity, not isolation**.

## Where to run it

- A trusted LAN, or through an SSH tunnel or VPN.
- **Not** on an interface exposed to a network you do not control. The primary
  development machine for this project is a laptop that roams onto café Wi-Fi;
  that is exactly the case to avoid.
- `-b <address>` binds to a single interface. The default is all interfaces,
  matching the convention of `telnetd` on other systems — but note that the
  convention is safe there *because* `inetd` runs `login` first. Bind narrowly
  if you are unsure.

## The development bypass

`-a` disables authentication entirely, for development on a machine whose owner
is not present to type a password.

It is **off by default**, it announces itself in the log, and it announces
itself **to the connecting client**. It exists so that work can continue without
a credential; it is not a supported way to run the daemon. If you see the
warning banner on connect, the daemon is serving unauthenticated shells.

Without the bypass, if `usergroup.library` cannot be opened the daemon
**refuses to start** rather than falling back to serving unauthenticated
sessions. Failing to start is a visible fault; failing open is a silent one.

## Status

Authentication is implemented but **not yet verified against a real account** —
it has been exercised only through its host-side policy tests. Until it has been
run against a MorphOS user with a password set, treat it as untested code.
