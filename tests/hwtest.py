#!/usr/bin/env python3
"""
hwtest -- drive a running telnetd on real hardware from the build host.

This exists because telnetd.c has no host coverage: the session lifecycle, the
login state machine and the output queue are the parts carrying the most logic
and the only ones with no tests.  They can only be exercised against the real
thing, so this drives the real thing and asserts on what comes back.

It is SAFE BY CONSTRUCTION -- it opens sockets and types.  Nothing here runs a
destructive command on Morphy, and the one thing that could (checking for
stranded processes) is a read-only `status` through the job queue, run by hand.

    python3 tests/hwtest.py <host> <port> <user> <password> [test...]
"""

import socket, sys, time

IAC, DONT, DO, WONT, WILL, SB, SE = 255, 254, 253, 252, 251, 250, 240
OPT_NAWS = 31

class Telnet:
    """Barely enough client to be an honest peer: answer negotiation, strip
    commands, hand back plain bytes."""

    def __init__(self, host, port, rows=24, cols=80, timeout=20):
        self.rows, self.cols = rows, cols
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(timeout)
        self.buf = b""

    def _negotiate(self, verb, opt):
        if verb == DO:
            # We agree to exactly one thing, so NAWS can be tested end to end.
            if opt == OPT_NAWS:
                self.sock.sendall(bytes([IAC, WILL, OPT_NAWS]))
                self.send_naws()
            else:
                self.sock.sendall(bytes([IAC, WONT, opt]))
        elif verb == WILL:
            self.sock.sendall(bytes([IAC, DONT, opt]))

    def send_naws(self):
        """RFC 1073: a dimension byte of 255 is data and must be sent as
        IAC IAC, exactly like any other 255 in the stream.

        Without this the harness is the non-conforming end: a cols=255 test
        would make a correct daemon look broken and send us hunting a bug in
        the code under test. That is the third instrument-not-subject error on
        this project today, and this one was in our own test kit."""
        body = [self.cols >> 8, self.cols & 0xFF,
                self.rows >> 8, self.rows & 0xFF]
        escaped = []
        for b in body:
            escaped.append(b)
            if b == IAC:
                escaped.append(IAC)
        self.sock.sendall(bytes([IAC, SB, OPT_NAWS] + escaped + [IAC, SE]))

    def _feed(self, data):
        out, i = b"", 0
        while i < len(data):
            c = data[i]
            if c != IAC:
                out += bytes([c]); i += 1; continue
            if i + 1 >= len(data): break
            v = data[i + 1]
            if v == IAC:
                out += b"\xff"; i += 2
            elif v in (DO, DONT, WILL, WONT):
                if i + 2 >= len(data): break
                self._negotiate(v, data[i + 2]); i += 3
            elif v == SB:
                j = data.find(bytes([IAC, SE]), i)
                i = len(data) if j < 0 else j + 2
            else:
                i += 2
        return out

    def read_until(self, needle, timeout=20):
        deadline = time.time() + timeout
        needle = needle.encode() if isinstance(needle, str) else needle
        while needle not in self.buf:
            if time.time() > deadline:
                raise TimeoutError("never saw %r; got %r" % (needle, self.buf[-400:]))
            self.sock.settimeout(max(0.1, deadline - time.time()))
            try:
                chunk = self.sock.recv(4096)
            except socket.timeout:
                continue
            if not chunk:
                raise EOFError("peer closed; got %r" % self.buf[-400:])
            self.buf += self._feed(chunk)
        return self.buf

    def drain(self, seconds):
        """Read whatever arrives for a while. Returns everything seen."""
        deadline = time.time() + seconds
        while time.time() < deadline:
            self.sock.settimeout(max(0.1, deadline - time.time()))
            try:
                chunk = self.sock.recv(4096)
            except socket.timeout:
                continue
            if not chunk:
                break
            self.buf += self._feed(chunk)
        return self.buf

    def write(self, s):
        self.sock.sendall(s.encode() if isinstance(s, str) else s)

    def login(self, user, password):
        self.read_until("login:")
        self.write(user + "\r\n")
        self.read_until("password:")
        self.write(password + "\r\n")

    def close(self):
        try: self.sock.close()
        except Exception: pass


def ok(name):   print("  ok   %s" % name)
def fail(name, why): print("  FAIL %s -- %s" % (name, why)); return False


# ---------------------------------------------------------------- tests

def test_sequential_logins(host, port, user, pw, n=15):
    """The signal-bit fix.  Every CreateMsgPort() used to burn one of about a
    dozen signal bits permanently, so session 13 was refused outright."""
    print("[1] %d sequential logins -- ports must come back" % n)
    for i in range(1, n + 1):
        try:
            t = Telnet(host, port)
            t.login(user, pw)
            t.read_until(">", timeout=25)          # a Shell prompt
            t.write("version\r\n")
            t.read_until("MorphOS", timeout=25)
            t.write("endcli\r\n")
            t.close()
        except Exception as e:
            return fail("login %d of %d" % (i, n), e)
        if i % 5 == 0:
            print("       %d ok" % i)
    ok("%d logins, none refused" % n)
    return True


def test_disconnect_midcommand(host, port, user, pw):
    """The stranded-Shell fix.  Ending the session at the moment of disconnect
    left the Shell writing to a port nobody would read again, forever."""
    print("[2] disconnect while a command is running")
    try:
        t = Telnet(host, port)
        t.login(user, pw)
        t.read_until(">", timeout=25)
        t.write("list SYS: all\r\n")
        time.sleep(1.0)                            # let it get going
        t.close()                                  # and vanish mid-flight
    except Exception as e:
        return fail("disconnect", e)
    ok("disconnected mid-command (now check Status on Morphy)")
    print("       -> expect NO leftover 'telnetd session' process,")
    print("          and 'reaped a console' or 'session ended' in the log")
    return True


def test_login_while_busy(host, port, user, pw):
    """The auth fix.  authenticate() used to run from the accept path with its
    own WaitSelect, so nothing else was serviced while anyone was typing."""
    print("[3] log in while another session is mid-command")
    try:
        busy = Telnet(host, port)
        busy.login(user, pw)
        busy.read_until(">", timeout=25)
        busy.write("list SYS: all\r\n")

        start = time.time()
        second = Telnet(host, port)
        second.read_until("login:", timeout=10)    # must arrive while #1 runs
        elapsed = time.time() - start
        second.login(user, pw)
        second.read_until(">", timeout=25)
        second.write("version\r\n")
        second.read_until("MorphOS", timeout=25)
        second.write("endcli\r\n"); second.close()
        busy.write("endcli\r\n"); busy.close()
    except Exception as e:
        return fail("concurrent login", e)
    ok("second caller got a prompt in %.1fs and a working shell" % elapsed)
    return True


def test_one_segment_login(host, port, user, pw):
    """The segment fix.  Everything after the first CR used to be discarded, so
    a client that wrote both lines at once never had its password read."""
    print("[4] user, password and first command in ONE write")
    try:
        t = Telnet(host, port)
        t.read_until("login:")
        t.write("%s\r\n%s\r\nversion\r\n" % (user, pw))
        t.read_until("MorphOS", timeout=25)
        t.write("endcli\r\n"); t.close()
    except Exception as e:
        return fail("single-segment login", e)
    ok("logged in and ran a command from one segment")
    return True


def test_bulk_output(host, port, user, pw):
    """The output-queue fix.  net_out() ignored short and refused sends while
    telling the Shell everything had been taken."""
    print("[5] bulk output -- nothing may be silently lost")
    try:
        t = Telnet(host, port)
        t.login(user, pw)
        t.read_until(">", timeout=25)
        t.write("list SYS: all\r\n")
        t.write("echo \"HWTEST-END-MARKER\"\r\n")
        t.read_until("HWTEST-END-MARKER", timeout=60)
        size = len(t.buf)
        t.write("endcli\r\n"); t.close()
    except Exception as e:
        return fail("bulk output", e)
    ok("read %d bytes and the marker after it arrived intact" % size)
    return True


def test_bad_password(host, port, user):
    """A refused login must say so and close, not hang and not admit."""
    print("[6] a wrong password is refused")
    try:
        t = Telnet(host, port)
        t.login(user, "definitely-not-the-password")
        t.read_until("Login incorrect", timeout=15)
        t.close()
    except Exception as e:
        return fail("bad password", e)
    ok("refused, with a message")
    return True


ALL = {
    "logins":     lambda h, p, u, w: test_sequential_logins(h, p, u, w),
    "disconnect": test_disconnect_midcommand,
    "busy":       test_login_while_busy,
    "segment":    test_one_segment_login,
    "bulk":       test_bulk_output,
    "badpw":      lambda h, p, u, w: test_bad_password(h, p, u),
}

def main():
    if len(sys.argv) < 5:
        print(__doc__)
        print("tests: " + " ".join(ALL))
        return 2
    host, port, user, pw = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
    wanted = sys.argv[5:] or list(ALL)

    print("telnetd hardware tests -- %s:%d as %s\n" % (host, port, user))
    results = {}
    for name in wanted:
        if name not in ALL:
            print("no such test: %s" % name); return 2
        try:
            results[name] = bool(ALL[name](host, port, user, pw))
        except Exception as e:
            results[name] = False
            print("  FAIL %s -- unhandled: %s" % (name, e))
        print()

    bad = [k for k, v in results.items() if not v]
    print("%d of %d passed" % (len(results) - len(bad), len(results)))
    if bad:
        print("failed: " + ", ".join(bad))
    return 1 if bad else 0

if __name__ == "__main__":
    sys.exit(main())
