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

## There is no way to disable authentication

Earlier versions had a `-a` flag that skipped the login, for development on a
machine whose owner was not always present to type a password. **It has been
removed.** Passing `-a` now makes the daemon refuse to start and say why, so a
script carrying the old flag cannot quietly get a different daemon from the one
it asked for.

The guarantee is deliberately **structural rather than procedural**: it is not
that the bypass defaults to off, or that release builds are configured without
it — there is no code in the binary that can serve a session without checking a
password. A compile-time switch was considered and rejected for the same reason.
This is software that other people will build from source and redistribute, and
a daemon that can be *compiled* into handing out an unauthenticated shell is a
footgun aimed at whoever packages it next.

Consequences worth stating plainly:

- **If `usergroup.library` cannot be opened, the daemon refuses to start.**
  There is no longer any flag that could talk it past that. Failing to start is
  a visible fault; failing open is a silent one.
- **An account with no password, or one locked with `*`, is refused** rather
  than admitted. The out-of-the-box MorphOS state is a blank password.
- **Testing needs a real account**, the same as any other use. That is a
  deliberate cost: the alternative was a special case in the daemon that existed
  only for us.

## Status

**Authentication is implemented and exercised on real hardware**, against real
accounts in the system user database, including sustained programmatic use by
the fleet's job runner. A wrong password is refused with a single message that
does not distinguish "no such user" from "wrong password" from "no password
set"; a correct one gets a shell.

What that does **not** mean: this has had no outside security review, and the
protocol underneath it is plaintext. See the top of this document. The auth path
has had two adversarial code reviews, which found real defects in it — including
a denial of service reachable before login — and those are fixed, but "reviewed
twice and fixed" is not "proven".
