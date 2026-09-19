/*
 * telnetd -- a telnet daemon for MorphOS.
 *
 * M2: one session at a time, over a real socket.
 *
 * The three layers are deliberately separate, and only this file knows about
 * more than one of them:
 *
 *   telnet.c           RFC 854. Knows nothing about MorphOS.
 *   console_handler.c  the shell-attach layer. Knows nothing about sockets.
 *   telnetd.c          this file: sockets, DOS packets, and the glue between.
 *
 * An sshd replaces telnet.c and keeps the rest. That is the point of the split.
 *
 * THE EVENT LOOP is a single WaitSelect() over the socket and our message port
 * at once -- bsdsocket's WaitSelect takes an Exec signal mask as its sixth
 * argument, which is what lets one process wait on both worlds without threads
 * (SMP does not work on MorphOS anyway) and without polling.
 *
 * NO MEMORY PROTECTION. We never free the message port; see the teardown note.
 */

#include <exec/types.h>
#include <exec/ports.h>
#include <exec/memory.h>
#include <exec/tasks.h>
#include <dos/dos.h>
#include <dos/dosextens.h>
#include <dos/dostags.h>
#include <proto/exec.h>
#include <proto/dos.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <proto/socket.h>

#include <string.h>

#include <proto/usergroup.h>
#include <pwd.h>

#include "console_handler.h"
#include "telnet.h"
#include "auth.h"

struct Library *SocketBase = NULL;
struct Library *UserGroupBase = NULL;

/*
 * THERE IS NO WAY TO BYPASS AUTHENTICATION. That is deliberate and it is a
 * release requirement, not a default.
 *
 * A `-a` flag used to disable the login entirely, for development on a machine
 * whose owner was not always around to type a password. It was off by default
 * and it announced itself loudly, and it is still gone: this is software other
 * people will build from source and redistribute, and a daemon that can be
 * compiled or invoked into handing out an unauthenticated shell is a footgun
 * aimed at whoever packages it next. Removing it makes the guarantee
 * structural -- true of every build, rather than of correctly-configured ones.
 *
 * Testing that needs a shell uses a real account, which is what everything
 * else has to use anyway.
 */

/*
 * FIONBIO, spelled out.
 *
 * bsdsocket's ioctl codes live in gg/include/sys/filio.h, which is the ixemul
 * header tree -- off limits to a -noixemul build (SDK.readme ll.30-31), and
 * os-include has no equivalent. The value is the standard BSD encoding, and
 * filio.h:52 gives the definition it is derived from:
 *
 *     #define FIONBIO  _IOW('f', 126, int)
 *
 *     _IOW(g,n,t) = IOC_IN | ((sizeof(t) & IOCPARM_MASK) << 16)
 *                          | ((g) << 8) | (n)
 *     IOC_IN = 0x80000000, IOCPARM_MASK = 0x1fff, sizeof(int) = 4
 *
 *  =  0x80000000 | (4 << 16) | ('f' << 8) | 126  =  0x8004667E
 */
#define TD_FIONBIO 0x8004667EUL

/*
 * Socket error codes, spelled out for the same reason.
 *
 * bsdsocket's Errno() returns the BSD values, but the header that NAMES them is
 * gg/include/errno.h -- the ixemul tree again, off limits to a -noixemul build.
 * Taken from that header, lines 56 and 96:
 *
 *     #define EINTR   4
 *     #define EAGAIN 35        and  #define EWOULDBLOCK EAGAIN
 */
#define TD_EINTR         4
#define TD_EWOULDBLOCK  35

#define DEFAULT_PORT   23
#define MOUNT_NAME     "TELCON"
#define SHELL_COMMAND  "NewShell " MOUNT_NAME ":"
#define INBUF_SIZE     4096
#define MAX_DEFERRED   8

/*
 * Output waiting for the socket.
 *
 * A non-blocking send() takes what the kernel has room for and no more, and
 * net_out() used to ignore both the short count and the outright refusal while
 * telling the Shell every byte had been consumed. A slow link plus a chatty
 * command therefore lost output silently -- no error anywhere, just missing
 * text, which is the worst way for a remote shell to be wrong.
 *
 * So output is queued, and the Shell is made to WAIT rather than lied to. Once
 * the queue passes the high-water mark this session stops taking packets off
 * its console port at all, and the Shell's next write simply sits there
 * unanswered -- which is exactly what a full pipe does to a process on Unix.
 * Back-pressure, using the machinery that was already there.
 */
#define OUTBUF_SIZE    32768
#define OUTBUF_HIWATER  8192

/* Last resort when a single write is too big to queue: how long to wait for
 * the socket rather than drop it. Bounded, because every other session is
 * stopped meanwhile. */
#define OUT_STALL_SECS     2

/*
 * Consoles outlive their sessions, so there has to be somewhere to put them.
 *
 * When the client vanishes, the Shell does not stop existing: it is told EOF
 * and exits of its own accord, but that takes as long as whatever it was doing
 * takes. Ending the session at the moment of disconnect left the Shell writing
 * to a message port nobody would ever read again, so it blocked in WaitPort
 * forever -- one stranded process per abrupt disconnect, on a machine that
 * reclaims nothing until it is rebooted.
 *
 * A reaper is the rest of that session: the port and the packet accounting,
 * with the socket gone. It keeps answering until the Shell has closed
 * everything, and only then is the port done with.
 */
#define MAX_REAPERS      8

/* How long a disconnected session keeps its slot before a reaper takes over.
 * A Shell sitting at a prompt exits the instant it is told EOF; this is the
 * allowance for one that was mid-command. */
#define DRAIN_GRACE_SECS 10

/*
 * How long a reaper waits on a console that never became established.
 *
 * A session whose Shell never opened a console of its own can never satisfy
 * console_session_finished(), which requires `established`. Waiting forever for
 * that would pin a reaper and its signal bit on a session that failed at the
 * starting line -- so a console that never established and has since gone quiet
 * is treated as done. Nothing beyond the two launch handles was ever handed
 * out, and the helper closes those.
 *
 * A console that DID establish is never timed out: open handles mean a Shell is
 * genuinely still running, and answering it is the job.
 */
#define REAPER_QUIET_SECS 30

/*
 * How long a launched Shell has to open a console of its own.
 *
 * SESSION_IDLE_SECS below is defined and never used, and console_handler.h
 * still promises that "a session that never establishes is ended by the
 * caller's idle timeout" -- a guard that went with the iteration-counted timer
 * and was never replaced. Without it, a Shell that fails to start leaves a
 * session that can NEVER be finished: console_session_finished() requires
 * `established`, and session_expired() requires a departed peer. A client that
 * politely waits for a prompt then holds the slot for good, and four of those
 * take the daemon out of service.
 *
 * Generous, because it is a backstop and not a policy: a Shell opens its
 * console within a second or two of starting.
 */
#define ESTABLISH_SECS 120
/*
 * How long a session may sit doing nothing before we wind it down.
 *
 * Deliberately generous. Unix telnetd has no idle limit at all -- an idle
 * shell is the normal state of a remote login, not a fault -- so this exists
 * only as a safety net against a session nobody is attached to any more, not
 * as a policy about how fast a person should type. Two consecutive intervals
 * are required, so the real limit is twice this.
 */
#define SESSION_IDLE_SECS 300

/*
 * Time to complete a login, as an ABSOLUTE deadline from the moment of
 * connection. The old one was reset on every arriving byte, so it measured
 * inactivity instead -- and a client sending one character a minute could hold
 * the login open forever. Matches the usual telnetd/login convention.
 */
#define LOGIN_TIMEOUT_SECS 60

/* How long a refused or timed-out caller is kept alive so the reason reaches
 * them before the socket closes. */
#define BYE_LINGER_SECS     5

/* Where a session is in its life. Only PHASE_SHELL has a Shell behind it. */
enum SessionPhase
{
	PHASE_USER = 0,	/* collecting the username */
	PHASE_PASS,	/* collecting the password */
	PHASE_SHELL,	/* logged in: bytes belong to the Shell */
	PHASE_BYE	/* refused; flushing the last message, then closing */
};

#define HANDLE_IN   1
#define HANDLE_OUT  2
#define HANDLE_OPEN 3

/* Passed to the helper process; ReplyMsg'd back when it exits. */
struct SpawnMsg
{
	struct Message msg;
	BPTR  input;
	BPTR  output;
	APTR  console_port;
	LONG  rc;
	char  command_buf[32];
};

/*
 * A session, complete. Everything that used to live in run_session's locals is
 * here, because a session is no longer serviced by a loop of its own: several
 * are serviced in slices from one loop, so their state has to outlive any call.
 */
struct Session
{
	int                in_use;
	LONG               sock;
	struct TelnetState tn;
	struct ConsoleState con;

	/* Bytes from the network, already stripped of telnet commands. */
	unsigned char in[INBUF_SIZE];
	long          in_len;
	long          in_pos;
	int           peer_gone;
	ULONG         drain_deadline;	/* 0 == not draining; see DRAIN_GRACE_SECS */

	/* Bytes for the network that the socket has not taken yet. */
	unsigned char out[OUTBUF_SIZE];
	long          out_len;
	long          out_pos;

	struct MsgPort    *port;	/* the Shell's console */
	struct MsgPort    *replyport;	/* the helper's exit notification */
	struct SpawnMsg   *sm;
	struct FileHandle *fh_in, *fh_out;
	struct DosList    *devnode;
	char               mount_name[24];
	int                helper_done;

	/* Reads held because the socket had nothing yet. */
	struct DosPacket  *deferred[MAX_DEFERRED];
	long               ndef;

	/* The login dialogue, which is a phase of this session rather than a
	 * loop of its own. See the note above login_consume(). */
	int    phase;
	int    shell_started;
	ULONG  login_deadline;
	ULONG  bye_deadline;
	ULONG  establish_deadline;
	char   login_user[64];
	char   login_pass[128];
	long   login_n;
};

#define MAX_SESSIONS 4
static struct Session sessions[MAX_SESSIONS];

/*
 * A coarse wall clock, in seconds.
 *
 * DateStamp() is the clock a -noixemul build has, and using a real one is the
 * point: the idle timer this replaces counted loop iterations instead, so a
 * limit measured in seconds expired in milliseconds. ds_Tick is 1/50s.
 */
static ULONG now_secs(void)
{
	struct DateStamp ds;

	DateStamp(&ds);
	return (ULONG)ds.ds_Days * 86400u
	     + (ULONG)ds.ds_Minute * 60u
	     + (ULONG)ds.ds_Tick / 50u;
}

/* ------------------------------------------------------------------ */
/* Message ports are a scarce resource, so they are reused, not discarded.
 *
 * CreateMsgPort() allocates an Exec SIGNAL BIT, and a task has 32 of them with
 * the low 16 reserved. Never releasing a port therefore did not merely leak a
 * few hundred bytes as the teardown note claimed -- it leaked one of about a
 * dozen signal bits, so after that many logins CreateMsgPort() returned NULL
 * and every subsequent caller was refused with "session setup failed" until
 * the daemon was restarted. The memory was the cheap part.
 *
 * Recycling is not the same gamble as freeing, which is why it is allowed here
 * when freeing still is not. A freed port is memory a Shell might PutMsg into,
 * and that kills the machine. A recycled port stays valid and stays ours; the
 * worst a stray packet can do is arrive at a port we are still reading. It is
 * only ever offered a port whose session finished cleanly, and it is refused
 * if anything is still queued on it.
 */
#define MAX_PORT_POOL (MAX_SESSIONS + MAX_REAPERS)
static struct MsgPort *port_pool[MAX_PORT_POOL];
static long            port_pool_n;

static struct MsgPort *port_get(void)
{
	while (port_pool_n > 0)
	{
		struct MsgPort *p = port_pool[--port_pool_n];
		if (p)
			return p;
	}
	return CreateMsgPort();
}

static void port_put(struct MsgPort *p)
{
	int empty;

	if (p == NULL)
		return;

	/* A message still on the queue means something out there believes this
	 * is its console. Leak it rather than hand it to the next caller. */
	Forbid();
	empty = (p->mp_MsgList.lh_TailPred == (struct Node *)&p->mp_MsgList);
	Permit();

	if (!empty || port_pool_n >= MAX_PORT_POOL)
		return;

	port_pool[port_pool_n++] = p;
}

/* ------------------------------------------------------------------ */
/* A session whose client is gone, kept alive until its Shell has finished. */

struct Reaper
{
	int                 in_use;
	struct MsgPort     *port;
	struct ConsoleState con;
	ULONG               quiet_deadline;
};

static struct Reaper reapers[MAX_REAPERS];

/* There is nothing to read from and nowhere to write to. Reporting EOF is what
 * makes the Shell exit; accepting writes is what lets it get that far. */
static long reaper_read(void *ctx, void *buf, long len)
{
	(void)ctx; (void)buf; (void)len;
	return -1;
}

static long reaper_write(void *ctx, const void *buf, long len)
{
	(void)ctx; (void)buf;
	return len;
}

/*
 * READY HANDSHAKE.
 *
 * -d used to report success on the strength of having forked. The child then
 * discovered it could not bind and had nowhere to say so, because the parent
 * had already exited announcing victory -- so starting on an occupied port gave
 * rc=0, a log file, a live process, and a port answering from somebody else's
 * daemon, with a supervisor going green over it.
 *
 * The parent therefore waits to be TOLD the child is listening. The channel is
 * a port the PARENT creates and names, passed to the child on its command line.
 *
 * It is deliberately not a well-known name derived from the TCP port. MorphOS
 * reclaims nothing at exit, so a daemon that crashes -- or is Break-ed while
 * wedged, both of which happened here -- would leave a public port behind with
 * nothing running. Anything treating that name as "a daemon is running" would
 * then refuse to start for a reason that is no longer true, and only a reboot
 * would clear it. A per-launch name cannot go stale: it lives exactly as long
 * as the parent that is waiting on it.
 *
 * bind() remains the only authority on whether a port is free. This says only
 * "a child of MINE reached listen()", which is a positive signal and never a
 * negative one.
 */
static void ready_portname(char *out, long max)
{
	static const char pfx[] = "telnetd-ready-";
	ULONG v = (ULONG)FindTask(NULL);
	int n = 0, i;

	while (pfx[n] && n < max - 12) { out[n] = pfx[n]; n++; }
	for (i = 28; i >= 0 && n < max - 1; i -= 4)
	{
		int d = (int)((v >> i) & 0xF);
		out[n++] = (char)(d < 10 ? '0' + d : 'a' + d - 10);
	}
	out[n] = '\0';
}

/* Configuration, parsed once and read by the daemon process. */
static LONG         cfg_port      = DEFAULT_PORT;
static LONG         cfg_wait      = 0;
static CONST_STRPTR cfg_bind      = NULL;
static CONST_STRPTR cfg_logfile   = NULL;
static CONST_STRPTR cfg_readyport = NULL;
static LONG         cfg_netwait   = 0;


/* ------------------------------------------------------------------ */

/*
 * Diagnostics go to a file when -l is given.
 *
 * stdout is useless when this runs detached or when the job that launched it
 * times out: the output goes with it, and a wedge becomes unexplainable. The
 * probe learned the same lesson -- instrumentation has to outlive the failure
 * it is describing.
 */
/*
 * The log is opened, appended to, and closed FOR EVERY LINE.
 *
 * It used to be held open for the daemon's whole life, and that had two
 * consequences, both reported from the far end by a second implementer.
 *
 * A running daemon's log could not be read AT ALL -- Type, Copy and a POSIX
 * read all failed with "object is in use" -- so the only way to see what a
 * daemon was doing was to stop the daemon and destroy the state you wanted to
 * look at. And any exit that skipped the one Close() left the file locked by a
 * process that no longer existed, until reboot, which is how a failed boot came
 * to make its own explanation unreadable.
 *
 * Both are the same fault: the diagnostic was unavailable exactly when it was
 * needed. A few DOS calls per line is nothing next to that -- this logs a
 * handful of lines per session, never in the data path.
 */
static int log_started = 0;	/* first write truncates, the rest append */
static int log_enabled = 0;	/* only the daemon writes; the parent must not */

static void log_line(CONST_STRPTR text, LONG len)
{
	BPTR f;

	if (!cfg_logfile || !log_enabled || len <= 0)
		return;

	f = Open(cfg_logfile, log_started ? MODE_READWRITE : MODE_NEWFILE);
	if (!f)
		return;

	if (log_started)
		Seek(f, 0, OFFSET_END);

	Write(f, (APTR)text, len);
	Close(f);
	log_started = 1;
}

static void say(CONST_STRPTR s)
{
	LONG len = (LONG)strlen(s);

	if (cfg_logfile && log_enabled)
	{
		log_line(s, len);
	}
	else
	{
		BPTR out = Output();
		if (out)
			Write(out, (APTR)s, len);
	}
}

static void say_num(CONST_STRPTR prefix, LONG value)
{
	char buf[32];
	char *p = buf + sizeof(buf);
	ULONG v;
	BOOL neg = FALSE;

	if (value < 0) { neg = TRUE; v = (ULONG)(-value); } else v = (ULONG)value;

	*--p = '\n';
	if (v == 0) *--p = '0';
	else while (v > 0 && p > buf) { *--p = (char)('0' + (v % 10)); v /= 10; }
	if (neg && p > buf) *--p = '-';

	say(prefix);
	if (cfg_logfile && log_enabled)
	{
		log_line((CONST_STRPTR)p, (LONG)(buf + sizeof(buf) - p));
	}
	else
	{
		BPTR out = Output();
		if (out)
			Write(out, p, (LONG)(buf + sizeof(buf) - p));
	}
}

/* ------------------------------------------------------------------ */
/* Callbacks: telnet <-> console                                       */

/* Bytes queued and still owed to the socket. */
static long net_pending(const struct Session *s)
{
	return s->out_len - s->out_pos;
}

/*
 * Push what the socket will take. Never blocks, never reports failure: a
 * refusal is indistinguishable from "would block" without errno, and the main
 * loop is already watching for both -- writability brings us back here, and a
 * genuinely dead peer shows up as recv() returning 0.
 */
static void net_flush(struct Session *s)
{
	if (s->sock < 0)
		return;

	while (s->out_pos < s->out_len)
	{
		LONG n = send(s->sock, (APTR)(s->out + s->out_pos),
		              s->out_len - s->out_pos, 0);
		if (n <= 0)
			break;
		s->out_pos += n;
	}

	if (s->out_pos >= s->out_len)
		s->out_len = s->out_pos = 0;
	else if (s->out_pos > 0)
	{
		memmove(s->out, s->out + s->out_pos, s->out_len - s->out_pos);
		s->out_len -= s->out_pos;
		s->out_pos  = 0;
	}
}

/*
 * Make room for an oversized write.
 *
 * Only reachable when one ACTION_WRITE is larger than the whole queue, which
 * the high-water mark makes rare -- but "rare" is not "never", and a program
 * may Write() any size it likes. Waiting a bounded moment for the socket is
 * better than dropping the data; the cap exists because every other session is
 * stopped while we do it.
 */
static int net_stall(struct Session *s)
{
	ULONG deadline = now_secs() + OUT_STALL_SECS;

	while (net_pending(s) > 0 && now_secs() <= deadline)
	{
		fd_set wr;
		struct timeval tv;
		LONG sigs = 0;

		FD_ZERO(&wr);
		FD_SET(s->sock, &wr);
		tv.tv_sec = 1; tv.tv_usec = 0;

		if (WaitSelect(s->sock + 1, NULL, &wr, NULL, &tv, (ULONG *)&sigs) < 0)
			break;
		net_flush(s);
	}

	return net_pending(s) < OUTBUF_SIZE;
}

static void net_out(void *ctx, const unsigned char *buf, long len)
{
	struct Session *s = (struct Session *)ctx;

	if (s->sock < 0 || len <= 0)
		return;

	while (len > 0)
	{
		long room = OUTBUF_SIZE - s->out_len;
		long n;

		if (room <= 0)
		{
			net_flush(s);
			room = OUTBUF_SIZE - s->out_len;
			if (room > 0)
				continue;

			/*
			 * NEVER STALL FOR A CLIENT THAT HAS NOT LOGGED IN.
			 *
			 * net_stall() holds up the entire daemon for a couple of
			 * seconds. Before login the only output is our own
			 * prompts and option replies -- and both are generated
			 * PER INPUT BYTE, so a stranger who connects, never
			 * reads, and sends 100 KB of carriage returns could make
			 * every 1024-byte read trigger some two thousand stalls
			 * and freeze all four sessions and the accept loop for
			 * over an hour. The login deadline could not fire,
			 * because the loop never got back to it.
			 *
			 * A caller who will not read its own login prompt is
			 * owed nothing. Hang up on it.
			 */
			if (s->phase != PHASE_SHELL)
			{
				say("telnetd: caller is not reading its own prompt; dropping it\n");
				s->peer_gone = 1;
				return;
			}

			if (!net_stall(s))
			{
				say("telnetd: output queue full -- DROPPING shell output\n");
				return;
			}
			continue;
		}

		n = (len < room) ? len : room;
		CopyMem((APTR)buf, s->out + s->out_len, n);
		s->out_len += n;
		buf += n;
		len -= n;
	}

	net_flush(s);
}

static void net_size(void *ctx, long rows, long cols)
{
	struct Session *s = (struct Session *)ctx;

	/* Straight through to the console layer, which answers CSI SP q from
	 * whatever this last said. There is no resize notification on MorphOS,
	 * so this value is only ever read when a program asks. */
	console_set_window_size(&s->con, rows, cols);
}

/* The Shell wants input. See console_handler.h for the 0 / -1 contract:
 * 0 means "not yet, hold the packet", -1 means the peer is gone. */
static long shell_read(void *ctx, void *buf, long len)
{
	struct Session *s = (struct Session *)ctx;
	long avail = s->in_len - s->in_pos;
	long n;

	if (avail <= 0)
		return s->peer_gone ? -1 : 0;

	n = (len < avail) ? len : avail;
	CopyMem(s->in + s->in_pos, buf, n);
	s->in_pos += n;

	if (s->in_pos >= s->in_len)
		s->in_len = s->in_pos = 0;

	return n;
}

/* The Shell produced output. Escape it and put it on the wire. */
static long shell_write(void *ctx, const void *buf, long len)
{
	struct Session *s = (struct Session *)ctx;

	telnet_output(&s->tn, (const unsigned char *)buf, len);
	return len;
}

/* ------------------------------------------------------------------ */
/* Authentication                                                       */

static void net_write_str(struct Session *s, CONST_STRPTR text)
{
	telnet_output(&s->tn, (const unsigned char *)text, (long)strlen((const char *)text));
}

/* ------------------------------------------------------------------ */
/* The login dialogue, as a phase of the session                        */

/*
 * This used to be a loop of its own, called straight from the accept path,
 * with its own WaitSelect() on the one socket it cared about.
 *
 * While it ran, NOTHING ELSE WAS SERVICED -- not another session's socket, not
 * a console port, not a new connection. Every established session's Shell sat
 * on packets nobody was there to answer. And the deadline was reset on each
 * arriving byte, so it timed inactivity rather than the login: one client
 * sending a character every 59 seconds could hold the whole daemon still for
 * as long as it liked. A program whose entire selling point is multiplexing
 * had a one-connection denial of service in its front door.
 *
 * So it is a state machine now, fed from the main loop as bytes arrive, with
 * an absolute deadline fixed when the caller connects.
 */

static int  session_launch_shell(struct Session *s);

static void session_bye(struct Session *s, CONST_STRPTR why)
{
	if (why)
		net_write_str(s, why);
	s->phase        = PHASE_BYE;
	s->bye_deadline = now_secs() + BYE_LINGER_SECS;
	net_flush(s);
}

static void session_login_timeout(struct Session *s)
{
	say("telnetd: login timed out\n");
	session_bye(s, (CONST_STRPTR)"\r\nLogin timed out.\r\n");
}

/*
 * Forget the credential everywhere it has been.
 *
 * The typed password reaches two places -- the field, and the decoded input
 * buffer it arrived in -- and wiping only the obvious one leaves it legible in
 * the other. Only the part of the buffer the login CONSUMED is wiped: anything
 * after it was typed for the Shell, and a client that sends its first command
 * in the same segment as its password must not lose it.
 */
static void login_forget(struct Session *s)
{
	long i;

	for (i = 0; i < (long)sizeof(s->login_pass); i++)
		s->login_pass[i] = 0;
	for (i = 0; i < s->in_pos && i < INBUF_SIZE; i++)
		s->in[i] = 0;
}

/* Everything, for a slot about to be handed to somebody else. */
static void login_forget_all(struct Session *s)
{
	long i;

	for (i = 0; i < (long)sizeof(s->login_pass); i++)
		s->login_pass[i] = 0;
	for (i = 0; i < (long)sizeof(s->login_user); i++)
		s->login_user[i] = 0;
	for (i = 0; i < INBUF_SIZE; i++)
		s->in[i] = 0;
	s->in_len = s->in_pos = 0;
}

/*
 * Decide, using the system's own user database.
 *
 * The daemon never stores a credential: getpwnam() gives us a salted hash and
 * crypt() turns what was typed into something comparable.
 */
static void login_finish(struct Session *s)
{
	struct passwd *pw;
	char salt[64];
	enum AuthResult res;

	pw = getpwnam((STRPTR)s->login_user);
	salt[0] = '\0';
	if (pw != NULL)
	{
		/* The library knows the right salt for this entry's hash format;
		 * choosing one ourselves would only work by accident. */
		ug_GetSalt(pw, (STRPTR)salt, sizeof(salt));
	}
	else
	{
		LONG e = ug_GetErr();
		say_num("telnetd: getpwnam failed, ug_GetErr = ", e);
	}

	/*
	 * THE STORED HASH IS THE SALT.
	 *
	 * crypt() takes the whole stored string as its salt argument and reads
	 * out whatever prefix its format needs -- two characters for classic
	 * DES, "$1$...$" for MD5. Passing a salt obtained separately only works
	 * if it happens to match the format of the stored entry, and a mismatch
	 * fails as an ordinary wrong password with nothing to distinguish it.
	 *
	 * ug_GetSalt() is kept as a fallback for an entry whose format crypt()
	 * cannot infer from the hash alone.
	 */
	{
		const char *saltp = (pw && pw->pw_passwd && pw->pw_passwd[0])
		                    ? (const char *)pw->pw_passwd
		                    : (const char *)salt;

		res = auth_policy(pw ? pw->pw_passwd : NULL,
		                  (pw && s->login_pass[0])
		                      ? (const char *)crypt((STRPTR)s->login_pass,
		                                            (STRPTR)saltp)
		                      : NULL);
	}

	login_forget(s);

	say("telnetd: login '");
	say((CONST_STRPTR)s->login_user);
	say("' -> ");
	say((CONST_STRPTR)auth_result_name(res));
	say("\n");

	if (res != AUTH_OK)
	{
		/* One message for every failure: never tell a stranger whether
		 * the account exists or merely has no password. */
		session_bye(s, (CONST_STRPTR)"\r\nLogin incorrect.\r\n");
		return;
	}

	net_write_str(s, (CONST_STRPTR)"\r\n");
	if (!session_launch_shell(s))
		session_bye(s, (CONST_STRPTR)
			"\r\ntelnetd: could not create a console for this session.\r\n");
}

/*
 * Consume as much of the decoded input as belongs to the login.
 *
 * Whatever is left after the password's newline stays in the buffer for the
 * Shell. That matters: a client that sends both lines in one segment -- which
 * an automated caller does as a matter of course -- used to have everything
 * after the first CR thrown away, so its password never arrived at all.
 *
 * We told the client WILL ECHO, so hiding the password is simply a matter of
 * not echoing it. There is no mode to switch; we were always the one echoing.
 */
static void login_consume(struct Session *s)
{
	while (s->in_pos < s->in_len
	       && (s->phase == PHASE_USER || s->phase == PHASE_PASS))
	{
		int   user  = (s->phase == PHASE_USER);
		char *field = user ? s->login_user : s->login_pass;
		long  max   = user ? (long)sizeof(s->login_user)
		                   : (long)sizeof(s->login_pass);
		unsigned char c = s->in[s->in_pos++];

		if (c == '\r' || c == '\n')
		{
			field[s->login_n] = '\0';
			s->login_n = 0;
			net_write_str(s, (CONST_STRPTR)"\r\n");

			if (user)
			{
				if (field[0] == '\0')
				{
					/* Nothing typed: ask again rather than
					 * spend the attempt. The deadline still
					 * bounds this. */
					net_write_str(s, (CONST_STRPTR)"login: ");
					continue;
				}
				s->phase = PHASE_PASS;
				net_write_str(s, (CONST_STRPTR)"password: ");
			}
			else
			{
				login_finish(s);
			}
			continue;
		}

		if (c == 8 || c == 127)			/* backspace / delete */
		{
			if (s->login_n > 0)
			{
				s->login_n--;
				if (user && telnet_should_echo(&s->tn))
					net_write_str(s, (CONST_STRPTR)"\b \b");
			}
			continue;
		}

		if (c < 32 || c > 126)
			continue;			/* ignore control bytes */

		if (s->login_n < max - 1)
		{
			field[s->login_n++] = (char)c;
			/*
			 * Only if the client still wants us to. We offer WILL
			 * ECHO and echo from the start, but a client may send
			 * DONT ECHO -- and echoing anyway gives it doubled
			 * characters it has no way to stop.
			 */
			if (user && telnet_should_echo(&s->tn))
				telnet_output(&s->tn, &c, 1);
		}
	}

	/*
	 * Nothing the login consumed may remain anywhere in this buffer.
	 *
	 * login_forget() wipes in[0 .. in_pos), which is right for one segment
	 * and wrong across several: in_pos is reset to 0 after each fully
	 * consumed read, so a password arriving split -- "hunter2" in one
	 * segment and the newline in the next, which is what typing looks like
	 * -- left its earlier pieces sitting above in_len, wiped by nobody until
	 * session_end.
	 */
	if (s->in_pos >= s->in_len)
	{
		long i;
		for (i = 0; i < INBUF_SIZE; i++)
			s->in[i] = 0;
		s->in_len = s->in_pos = 0;
	}
	else
	{
		/* A remainder was typed for the Shell: keep it, wipe behind it. */
		long rem = s->in_len - s->in_pos, i;

		memmove(s->in, s->in + s->in_pos, rem);
		for (i = rem; i < INBUF_SIZE; i++)
			s->in[i] = 0;
		s->in_len = rem;
		s->in_pos = 0;
	}
}

/* ------------------------------------------------------------------ */

static void spawn_helper(void)
{
	struct SpawnMsg *sm = NULL;
	struct TagItem attrtags[1];
	struct TagItem systags[6];

	attrtags[0].ti_Tag = TAG_DONE; attrtags[0].ti_Data = 0;

	if (!NewGetTaskAttrsA(NULL, &sm, sizeof(struct SpawnMsg *),
	                      TASKINFOTYPE_STARTUPMSG, attrtags) || sm == NULL)
		return;

	systags[0].ti_Tag = SYS_Input;      systags[0].ti_Data = (IPTR)sm->input;
	systags[1].ti_Tag = SYS_Output;     systags[1].ti_Data = (IPTR)sm->output;
	systags[2].ti_Tag = SYS_FilterTags; systags[2].ti_Data = (IPTR)FALSE;
	systags[3].ti_Tag = NP_ConsoleTask; systags[3].ti_Data = (IPTR)sm->console_port;
	systags[4].ti_Tag = NP_WindowPtr;   systags[4].ti_Data = (IPTR)-1;
	systags[5].ti_Tag = TAG_DONE;       systags[5].ti_Data = 0;

	sm->rc = SystemTagList((CONST_STRPTR)sm->command_buf, systags);

	Forbid();
	if (sm->input)  Close(sm->input);
	if (sm->output) Close(sm->output);
	sm->input = sm->output = 0;
	Permit();
}

static struct FileHandle *make_handle(struct MsgPort *port, LONG mode, LONG id)
{
	struct FileHandle *fh;
	struct TagItem tags[2];

	tags[0].ti_Tag = ADO_FH_Mode; tags[0].ti_Data = (IPTR)mode;
	tags[1].ti_Tag = TAG_DONE;    tags[1].ti_Data = 0;

	fh = (struct FileHandle *)AllocDosObject(DOS_FILEHANDLE, tags);
	if (fh == NULL)
		return NULL;

	fh->fh_Type        = port;
	fh->fh_Interactive = DOSTRUE;
	fh->fh_Arg1        = id;
	return fh;
}

/* ------------------------------------------------------------------ */

/* ------------------------------------------------------------------ */
/* A session is now started, serviced in slices, and ended -- rather than
 * owning a blocking loop. That is what lets one process serve several at
 * once, which matters because a second caller previously connected and then
 * silently received nothing at all.                                    */

/*
 * Answer everything queued on one console port.
 *
 * Shared by live sessions and reapers on purpose: a Shell winding down opens
 * and closes handles exactly as a live one does, and two copies of this loop
 * would eventually disagree about how to complete an open.
 *
 * `deferred` may be NULL, meaning this caller cannot hold a packet back; a
 * read that would block is then answered EOF instead.
 */
/*
 * ACTION_EXAMINE_FH -- fstat() on a console.
 *
 * Answered HERE and not in console_handler.c on purpose: it is the one packet
 * whose reply is a MorphOS structure written into the caller's memory, and that
 * layer is deliberately free of MorphOS types so it can be tested on the build
 * host. An sshd reusing the shell-attach layer needs this function too; it is
 * self-contained so it can be lifted whole.
 *
 * WHY IT MATTERS: ixemul turns fstat() into this packet, so EVERY ixemul binary
 * in the SDK stats its console. Refusing it looked harmless because pdksh
 * ignores the failure -- but that is luck, not design, and the trail only
 * started because pdksh was mis-reported as unusable over telnet and I
 * went looking for a fault in this handler.
 *
 * WHAT TO PUT IN IT, from ixemul's own source rather than guesswork
 * (ixemul.library/library/__fstat.c and stat.c):
 *
 *   - fib_DirEntryType = ST_PIPEFILE. stat.c maps ST_PIPEFILE to S_IFCHR, which
 *     is what a terminal should be. __fstat.c carries a complaint about
 *     handlers that "support EXAMINE_FH but don't know yet about ST_PIPEFILE,
 *     so console windows claim they're plain files", and does an extra Seek to
 *     catch those fakers. Reporting ST_FILE would make us one of them.
 *   - fib_Size 0, and it is only consulted when fib_DirEntryType is negative,
 *     which ST_PIPEFILE is.
 *   - fib_Protection 0. Amiga protection bits are ACTIVE LOW for RWED, and
 *     stat.c does `fib_Protection ^= 0xf` before reading them, so zero means
 *     read, write, execute and delete all permitted.
 *
 * isatty() does NOT depend on any of this -- ixemul implements it with
 * IsInteractive() -- so answering cannot break interactivity. That was the risk
 * worth checking before writing into somebody else's buffer, and the source
 * settled it.
 */
static int answer_examine_fh(struct DosPacket *pkt)
{
	struct FileInfoBlock *fib;
	const char *name = "CONSOLE";
	int i;

	if (pkt->dp_Type == ACTION_PARENT_FH
	 || pkt->dp_Type == ACTION_COPY_DIR_FH)
	{
		/*
		 * A console has no parent directory and no directory to copy.
		 * Say THAT, rather than "I do not know this action", which is a
		 * different claim: we know the action perfectly well and the
		 * object genuinely has no such thing.
		 *
		 * Both appear only once EXAMINE_FH starts succeeding -- ixemul's
		 * fstat goes on to build an st_ino and asks for them -- so they
		 * arrived as a direct consequence of answering that packet.
		 */
		ReplyPkt(pkt, DOSFALSE, ERROR_OBJECT_NOT_FOUND);
		return 1;
	}

	if (pkt->dp_Type != ACTION_EXAMINE_FH)
		return 0;

	fib = (struct FileInfoBlock *)BADDR((BPTR)pkt->dp_Arg2);
	if (fib == NULL)
	{
		ReplyPkt(pkt, DOSFALSE, ERROR_OBJECT_WRONG_TYPE);
		return 1;
	}

	memset(fib, 0, sizeof(*fib));

	fib->fib_DiskKey      = 0;
	fib->fib_DirEntryType = ST_PIPEFILE;
	fib->fib_EntryType    = ST_PIPEFILE;
	fib->fib_Protection   = 0;
	fib->fib_Size         = 0;
	fib->fib_NumBlocks    = 0;
	fib->fib_OwnerUID     = 0;
	fib->fib_OwnerGID     = 0;

	for (i = 0; name[i] && i < (int)sizeof(fib->fib_FileName) - 1; i++)
		fib->fib_FileName[i] = name[i];
	fib->fib_FileName[i] = '\0';
	fib->fib_Comment[0]  = '\0';

	DateStamp(&fib->fib_Date);

	ReplyPkt(pkt, DOSTRUE, 0);
	return 1;
}

static long service_port(struct MsgPort *port, struct ConsoleState *con,
                         struct DosPacket **deferred, long *ndef, long maxdef)
{
	struct Message *msg;
	long handled = 0;

	while ((msg = GetMsg(port)) != NULL)
	{
		handled++;
		struct DosPacket *pkt = (struct DosPacket *)msg->mn_Node.ln_Name;
		struct ConsoleReply r;
		void *bufarg = NULL;
		LONG  len = 0;

		if (pkt == NULL)
			continue;

		/* Packets whose answer is a MorphOS structure, not a decision. */
		if (answer_examine_fh(pkt))
			continue;

		if (pkt->dp_Type == ACTION_READ || pkt->dp_Type == ACTION_WRITE)
		{
			bufarg = (void *)pkt->dp_Arg2;
			len    = pkt->dp_Arg3;
		}

		{
			long before = con->unknown;

			r = console_dispatch(con, pkt->dp_Type, pkt->dp_Arg1,
			                     pkt->dp_Arg2, bufarg, len);

			/*
			 * Name every packet we could not answer.
			 *
			 * The console layer counts them; nothing ever said WHICH,
			 * so a program that failed here failed silently and looked
			 * like a platform limit. An ixemul binary asks for things
			 * a Shell never does, and this is the only place that can
			 * tell us what they were.
			 */
			if (con->unknown != before)
				say_num("telnetd: unanswered packet, dp_Type = ",
				        (LONG)pkt->dp_Type);
		}

		if (r.defer)
		{
			if (deferred && *ndef < maxdef)
			{
				deferred[(*ndef)++] = pkt;
				continue;
			}
			r.res1 = 0;	/* nowhere to hold it: EOF beats losing it */
			r.res2 = 0;
		}

		/* Complete an open the way a real handler does
		 * (ahi-handler/main.c:330-331). fh_Interactive is what makes
		 * NewShell accept the stream as a console at all. */
		if (r.res1 == DOSTRUE
		    && (pkt->dp_Type == ACTION_FINDINPUT
		     || pkt->dp_Type == ACTION_FINDOUTPUT
		     || pkt->dp_Type == ACTION_FINDUPDATE))
		{
			struct FileHandle *nfh =
				(struct FileHandle *)BADDR((BPTR)pkt->dp_Arg1);
			if (nfh)
			{
				nfh->fh_Arg1        = HANDLE_OPEN;
				nfh->fh_Interactive = DOSTRUE;
			}
		}

		ReplyPkt(pkt, r.res1, r.res2);
	}

	return handled;
}

/*
 * Hand a departing session's console to a reaper.
 *
 * The console state is copied verbatim -- the handle count is the whole point,
 * since it is what says when the Shell has let go -- and only the two ends of
 * it are rebound to a reaper that reads EOF and swallows output.
 */
static int reaper_available(void)
{
	int i;

	for (i = 0; i < MAX_REAPERS; i++)
		if (!reapers[i].in_use)
			return 1;
	return 0;
}

static int reaper_adopt(struct Session *s)
{
	int i;

	if (s->port == NULL)
		return 0;

	for (i = 0; i < MAX_REAPERS; i++)
		if (!reapers[i].in_use)
			break;
	if (i == MAX_REAPERS)
		return 0;

	reapers[i].port     = s->port;
	reapers[i].con      = s->con;		/* struct copy, accounting included */
	reapers[i].con.read_fn  = reaper_read;
	reapers[i].con.write_fn = reaper_write;
	reapers[i].con.io_ctx   = &reapers[i];
	reapers[i].con.draining = 1;
	reapers[i].quiet_deadline = now_secs() + REAPER_QUIET_SECS;
	reapers[i].in_use   = 1;

	say("telnetd: console handed to a reaper; its shell has not exited yet\n");
	return 1;
}

static void reaper_service(struct Reaper *r)
{
	int done;

	if (service_port(r->port, &r->con, NULL, NULL, 0) > 0)
		r->quiet_deadline = now_secs() + REAPER_QUIET_SECS;

	done = console_session_finished(&r->con)
	    || (!r->con.established && now_secs() >= r->quiet_deadline);

	if (done)
	{
		port_put(r->port);
		r->port   = NULL;
		r->in_use = 0;
		say("telnetd: reaped a console; its port is available again\n");
	}
}

static void session_end(struct Session *s)
{
	/* Anything still held must be answered or the Shell waits forever. */
	while (s->ndef > 0)
		ReplyPkt(s->deferred[--s->ndef], 0, 0);

	if (s->devnode && RemDosEntry(s->devnode))
		FreeDosEntry(s->devnode);
	s->devnode = NULL;

	/*
	 * The port is still never FREED -- freeing one a Shell might hold takes
	 * the machine down rather than failing politely, and our own packet
	 * accounting is the only thing that could vouch for it. But it is no
	 * longer simply abandoned either, because abandoning it leaked a signal
	 * bit and stranded whatever was still writing to it.
	 *
	 * Finished cleanly: recycle it, which is a weaker claim than freeing --
	 * the memory stays valid and stays ours either way.
	 * Not finished: a reaper keeps answering it until the Shell lets go.
	 */
	if (!s->shell_started)
	{
		/*
		 * No Shell was ever pointed at any of this, so it is all still
		 * ours -- and the file handles really do have to go back.
		 * AllocDosObject'd in session_start for EVERY accepted caller,
		 * they were only ever freed by the helper's Close() (when a
		 * Shell was launched) or by the fail: path. A refused login, a
		 * timed-out one, or "authentication unavailable" leaked both,
		 * before any authentication, without limit, until reboot.
		 */
		if (s->fh_in)  FreeDosObject(DOS_FILEHANDLE, s->fh_in);
		if (s->fh_out) FreeDosObject(DOS_FILEHANDLE, s->fh_out);
		port_put(s->port);
	}
	else if (s->helper_done && console_session_finished(&s->con))
		port_put(s->port);
	else if (!reaper_adopt(s))
	{
		/*
		 * Nothing will read this port again, so nothing should be
		 * signalled through it either. PA_IGNORE makes PutMsg enqueue
		 * and return: harmless while we live, and essential if we do
		 * not -- otherwise a Shell outliving the daemon signals a Task
		 * that has been freed, which is not an error, it is a dead
		 * machine.
		 */
		say("telnetd: no reaper free -- abandoning a console port\n");
		if (s->port)
			s->port->mp_Flags = PA_IGNORE;
	}
	s->port = NULL;

	if (s->helper_done || !s->shell_started)
	{
		/* !shell_started means no helper was ever created, so nothing
		 * else can be holding these. Leaving them was another signal
		 * bit gone per refused login. */
		if (s->replyport) DeleteMsgPort(s->replyport);
		if (s->sm)        FreeVec(s->sm);
	}
	else if (s->replyport)
	{
		/* Kept because the helper may still reply to it, but nobody
		 * will ever read it again -- so it must not signal us either. */
		s->replyport->mp_Flags = PA_IGNORE;
	}
	s->replyport = NULL;
	s->sm = NULL;

	/* The slot is reused, so nothing of this caller may be left legible in
	 * it for the next one. */
	login_forget_all(s);

	if (s->sock >= 0)
		CloseSocket(s->sock);
	s->sock = -1;
	s->in_use = 0;
	say("telnetd: session ended\n");
}

/*
 * True once there is nothing left to serve.
 *
 * `|| s->peer_gone` used to be part of this, and it was wrong. helper_done
 * goes true seconds into a session -- "NewShell <window>" returns once it has
 * LAUNCHED the shell, not when that shell exits -- so a disconnect made this
 * true immediately, while the Shell still held open handles. Its remaining
 * packets then went to a port nobody read again and it blocked forever.
 *
 * A dead peer is handled where it belongs instead: reads report EOF, the Shell
 * exits, and if it takes longer than DRAIN_GRACE_SECS a reaper finishes the
 * job so the session slot is not held hostage.
 */
static int session_finished(struct Session *s)
{
	if (!s->shell_started)
	{
		/* Nothing was ever spawned on this caller's behalf, so there is
		 * nothing to wind down -- only our own last words to get out. */
		if (s->peer_gone)
			return 1;
		if (s->phase == PHASE_BYE)
			return net_pending(s) == 0 || now_secs() >= s->bye_deadline;
		return 0;
	}

	return s->helper_done && console_session_finished(&s->con);
}

static int session_expired(struct Session *s)
{
	if (!s->shell_started)
		return 0;	/* bounded by the login deadline instead */

	/* Launched, but it never opened a console of its own. */
	if (!s->con.established
	    && s->establish_deadline != 0
	    && now_secs() >= s->establish_deadline)
		return 1;

	return s->peer_gone
	    && s->drain_deadline != 0
	    && now_secs() >= s->drain_deadline;
}

static int session_start(struct Session *s, LONG sock, LONG session_no)
{
	LONG yes = 1;

	memset(s, 0, sizeof(*s));
	s->in_use = 1;
	s->sock   = sock;
	s->ndef   = 0;
	s->phase  = PHASE_USER;
	s->login_deadline = now_secs() + LOGIN_TIMEOUT_SECS;

	/*
	 * A device name unique to this DAEMON as well as this session.
	 *
	 * Names used to be TEL00, TEL01... per session, which is fine for one
	 * daemon and wrong for two: a second instance starts numbering at TEL00
	 * as well, AddDosEntry fails for whichever asks second, and that
	 * session dies. Measured -- two daemons on different ports, and only
	 * the first to ask got a Shell.
	 *
	 * That is not a corner case in this design. The whole point of running
	 * development and production on separate ports is that one can be
	 * restarted freely while the other serves; a shared name would mean
	 * iterating on one takes down the other, which is the exact failure the
	 * split exists to prevent.
	 *
	 * The listening port is already unique per daemon, so it goes in the
	 * name: T<port><letter>, e.g. T2320A.
	 */
	{
		char *d = s->mount_name;
		LONG v = cfg_port;
		char digits[8];
		int nd = 0;

		*d++ = 'T';
		if (v <= 0) v = 0;
		do { digits[nd++] = (char)('0' + (v % 10)); v /= 10; } while (v > 0 && nd < 8);
		while (nd > 0) *d++ = digits[--nd];
		*d++ = (char)('A' + (session_no % 26));
		*d = '\0';
	}

	s->port      = port_get();
	s->replyport = CreateMsgPort();
	s->sm        = AllocVec(sizeof(struct SpawnMsg), MEMF_PUBLIC | MEMF_CLEAR);
	s->fh_in     = s->port ? make_handle(s->port, MODE_OLDFILE,  HANDLE_IN)  : NULL;
	s->fh_out    = s->port ? make_handle(s->port, MODE_NEWFILE, HANDLE_OUT) : NULL;

	if (!s->port || !s->replyport || !s->sm || !s->fh_in || !s->fh_out)
	{
		say("telnetd: session setup failed\n");
		goto fail;
	}

	/*
	 * Non-blocking from the very first byte.
	 *
	 * This used to be switched on after the login, because the login had a
	 * blocking loop of its own. It does not any more, and nothing this
	 * socket does may make the other sessions wait.
	 */
	IoctlSocket(s->sock, TD_FIONBIO, (APTR)&yes);

	/* The telnet layer must exist before the login: the dialogue is carried
	 * over it, and the password is hidden by our own choice not to echo. */
	telnet_init(&s->tn, net_out, net_size, s);
	console_init(&s->con, shell_read, shell_write, s, 2, 0);
	telnet_start(&s->tn);

	if (UserGroupBase == NULL)
	{
		say("telnetd: usergroup.library unavailable; refusing all logins\n");
		session_bye(s, (CONST_STRPTR)"\r\nAuthentication unavailable.\r\n");
		return 1;
	}

	/*
	 * From here the main loop drives it. The caller is accepted -- it has a
	 * slot and a deadline -- but nothing is spawned on its behalf until it
	 * has proved who it is.
	 */
	net_write_str(s, (CONST_STRPTR)"\r\nMorphOS telnetd\r\n\r\nlogin: ");
	return 1;

fail:
	/* Reachable only before any Shell exists, so these really are ours.
	 *
	 * The DOS entry goes first. CreateNewProc() failing left it published
	 * with dol_Task pointing at a port this same path then deleted, so
	 * anything that so much as listed the device -- or the session 26 logins
	 * later that reused the letter -- would have sent a packet into freed
	 * memory. */
	if (s->devnode && RemDosEntry(s->devnode))
		FreeDosEntry(s->devnode);
	s->devnode = NULL;

	if (s->fh_in)     FreeDosObject(DOS_FILEHANDLE, s->fh_in);
	if (s->fh_out)    FreeDosObject(DOS_FILEHANDLE, s->fh_out);
	if (s->sm)        FreeVec(s->sm);
	if (s->replyport) DeleteMsgPort(s->replyport);
	if (s->port)      port_put(s->port);
	if (s->sock >= 0) CloseSocket(s->sock);
	memset(s, 0, sizeof(*s));
	s->sock = -1;
	return 0;
}

/*
 * Everything that only happens once a caller has proved who it is.
 *
 * Kept apart from session_start() on purpose: until this runs, no Shell exists,
 * no device name is published, and nothing but a socket and a message port has
 * been spent on whoever is calling. A failed login therefore costs an
 * unauthenticated stranger almost nothing of ours.
 */
static int session_launch_shell(struct Session *s)
{
	struct TagItem proctags[6];

	s->devnode = MakeDosEntry((CONST_STRPTR)s->mount_name, DLT_DEVICE);
	if (s->devnode == NULL)
	{
		say("telnetd: MakeDosEntry failed\n");
		return 0;
	}
	s->devnode->dol_Task = s->port;

	if (!AddDosEntry(s->devnode))
	{
		say("telnetd: mount name already in use: ");
		say((CONST_STRPTR)s->mount_name);
		say("\n");
		FreeDosEntry(s->devnode);
		s->devnode = NULL;
		return 0;
	}

	s->sm->msg.mn_Node.ln_Type = NT_MESSAGE;
	s->sm->msg.mn_ReplyPort    = s->replyport;
	s->sm->msg.mn_Length       = sizeof(struct SpawnMsg);
	s->sm->input               = MKBADDR(s->fh_in);
	s->sm->output              = MKBADDR(s->fh_out);
	s->sm->console_port        = (APTR)s->port;

	{
		char *d = s->sm->command_buf;
		const char *p1 = "NewShell ";
		while (*p1) *d++ = *p1++;
		p1 = s->mount_name;
		while (*p1) *d++ = *p1++;
		*d++ = ':'; *d = '\0';
	}

	proctags[0].ti_Tag = NP_CodeType;   proctags[0].ti_Data = CODETYPE_PPC;
	proctags[1].ti_Tag = NP_Entry;      proctags[1].ti_Data = (IPTR)spawn_helper;
	proctags[2].ti_Tag = NP_StartupMsg; proctags[2].ti_Data = (IPTR)s->sm;
	proctags[3].ti_Tag = NP_Name;       proctags[3].ti_Data = (IPTR)"telnetd session";
	proctags[4].ti_Tag = NP_WindowPtr;  proctags[4].ti_Data = (IPTR)-1;
	proctags[5].ti_Tag = TAG_DONE;      proctags[5].ti_Data = 0;

	if (CreateNewProc(proctags) == NULL)
	{
		say("telnetd: could not start the shell\n");
		if (RemDosEntry(s->devnode))
			FreeDosEntry(s->devnode);
		s->devnode = NULL;
		return 0;
	}

	s->shell_started      = 1;
	s->phase              = PHASE_SHELL;
	s->establish_deadline = now_secs() + ESTABLISH_SECS;

	say("telnetd: session on ");
	say((CONST_STRPTR)s->mount_name);
	say(":\n");
	return 1;
}

/* One slice of work: whatever this session can do without blocking. */
static void session_service(struct Session *s, int readable, int writable)
{
	long i;

	if (writable)
		net_flush(s);

	/*
	 * Reclaim what the Shell has already read. Without this the buffer
	 * only ever emptied when it emptied COMPLETELY, so a session that was
	 * never quite drained filled up and then discarded everything typed
	 * after that -- silently, since telnet_input honours out_max and simply
	 * parses the overflow away.
	 */
	if (s->in_pos > 0)
	{
		if (s->in_pos < s->in_len)
		{
			memmove(s->in, s->in + s->in_pos, s->in_len - s->in_pos);
			s->in_len -= s->in_pos;
		}
		else
			s->in_len = 0;
		s->in_pos = 0;
	}

	if (s->sock >= 0 && readable)
	{
		unsigned char raw[1024];
		int  secret = (s->phase == PHASE_PASS || s->phase == PHASE_USER);
		long room   = INBUF_SIZE - s->in_len;
		LONG got;

		/*
		 * Ask for no more than we can keep.
		 *
		 * Dropping the socket from the read set when the buffer is FULL
		 * was 1023 bytes too late: this always asked for 1024 and then
		 * handed telnet_input only the remaining room, so everything
		 * past it was parsed and silently discarded. Paste 5 KB while
		 * the Shell is busy and the tail vanished with no trace.
		 *
		 * Safe because telnet_input never emits more bytes than it
		 * consumes -- its only two-for-one branch consumes two.
		 */
		if (room > (long)sizeof(raw))
			room = (long)sizeof(raw);
		if (room <= 0)
			goto no_read;

		got = recv(s->sock, raw, room, 0);

		if (got > 0)
		{
			long n = telnet_input(&s->tn, raw, got,
			                      s->in + s->in_len,
			                      INBUF_SIZE - s->in_len);
			s->in_len += n;
			if (s->phase != PHASE_SHELL)
				login_consume(s);
		}
		else if (got == 0)
		{
			s->peer_gone      = 1;
			s->drain_deadline = now_secs() + DRAIN_GRACE_SECS;
			console_begin_drain(&s->con);
			/*
			 * Throw the queue away. Nothing will ever send it now, so
			 * keeping it holds net_pending above the high-water mark
			 * forever -- which stops the console port being serviced
			 * at all, leaving the Shell blocked in WaitPort until a
			 * reaper happens to be free. Drain means drain.
			 */
			s->out_len = s->out_pos = 0;
			say("telnetd: peer closed; draining\n");
		}
		else
		{
			/*
			 * -1 is USUALLY just an empty non-blocking socket, and
			 * treating that as a hangup ended live sessions. But it
			 * is not always: a reset connection reports readable
			 * forever and fails every recv(), so taking every -1 for
			 * "nothing yet" spun this loop at full speed until the
			 * Shell happened to exit. Ask which it was.
			 */
			LONG e = Errno();

			if (e != TD_EWOULDBLOCK && e != TD_EINTR)
			{
				s->peer_gone      = 1;
				s->drain_deadline = now_secs() + DRAIN_GRACE_SECS;
				console_begin_drain(&s->con);
				s->out_len = s->out_pos = 0;
				say_num("telnetd: peer reset; draining, errno = ", e);
			}
		}

		/*
		 * This held the password on its way past.
		 *
		 * It goes AFTER the whole chain above, and deliberately: putting
		 * it in the middle bound the following "else if (got == 0)" to
		 * this test instead of to the read, so during a login -- when
		 * `secret` is always true -- a client hanging up was never
		 * noticed at all. The session then held its slot forever, and
		 * four callers took the daemon out of service.
		 */
		if (secret)
		{
			LONG k;
			for (k = 0; k < (LONG)sizeof(raw); k++)
				raw[k] = 0;
		}
	no_read: ;
	}

	/* Reads held back because the socket had nothing to give them. */
	for (i = 0; i < s->ndef; )
	{
		struct DosPacket *p = s->deferred[i];
		struct ConsoleReply r =
			console_dispatch(&s->con, p->dp_Type, p->dp_Arg1,
			                 p->dp_Arg2, (void *)p->dp_Arg2, p->dp_Arg3);

		if (r.defer) { i++; continue; }
		ReplyPkt(p, r.res1, r.res2);
		s->deferred[i] = s->deferred[--s->ndef];
	}

	/*
	 * Take packets only while there is somewhere to put the answers. Over
	 * the high-water mark the Shell's writes stay queued on the port,
	 * unanswered, and it blocks in WaitPort until the socket catches up --
	 * which is the whole point: back-pressure instead of discarded output.
	 */
	if (net_pending(s) < OUTBUF_HIWATER)
		service_port(s->port, &s->con, s->deferred, &s->ndef, MAX_DEFERRED);

	while (GetMsg(s->replyport) != NULL)
	{
		s->helper_done = 1;
		say_num("telnetd: helper finished, SystemTagList rc = ", s->sm->rc);
	}

	net_flush(s);
}

/* ------------------------------------------------------------------ */

/*
 * Configuration, held where a detached child can reach it.
 *
 * Parent and child share one address space on MorphOS, so the child reads what
 * the parent parsed. Nothing is passed through the startup message because
 * nothing needs to be: there is only ever one daemon per process image.
 */

static void daemon_main(void);

/*
 * Background ourselves, properly.
 *
 * `Run` is an AmigaDOS command that pdksh does not resolve -- the line silently
 * evaporates. The shell's own `&` starts a process that, with authentication
 * enabled, never binds at all.
 *
 * The obvious fix -- CreateNewProc() on a function in this image -- is worse
 * than it looks, and cost several hardware runs to understand. The child shares
 * this program's GLOBALS, including the library bases libnix opened at startup.
 * When the parent's main() returns, libnix's exit code CLOSES those bases. The
 * child is then holding a closed dos.library, so every DOS call it makes fails
 * while its own bsdsocket calls keep working -- which is exactly what was
 * observed: the port bound and listened, and nothing else worked, not even
 * writing a log file.
 *
 * So the daemon re-launches the BINARY, not a function: a fresh image gets its
 * own startup code and its own library bases and does not care what happens to
 * this process. SYS_Asynch means System() returns immediately and the new
 * program owns the handles it was given.
 */
static int detach(CONST_STRPTR self, int argc, char **argv)
{
	char cmd[512];
	int n = 0, i;
	struct TagItem systags[4];
	BPTR nil_in, nil_out;

	/* Rebuild our own command line without -d, so the child does not
	 * detach again and fork indefinitely. */
	{
		const char *p = (const char *)self;
		while (*p && n < (int)sizeof(cmd) - 2) cmd[n++] = *p++;
	}
	for (i = 1; i < argc && n < (int)sizeof(cmd) - 2; i++)
	{
		const char *a = argv[i];
		if (a[0] == '-' && a[1] == 'd')
			continue;
		cmd[n++] = ' ';
		while (*a && n < (int)sizeof(cmd) - 2) cmd[n++] = *a++;
	}
	/* Tell the child where to report that it is listening. */
	if (cfg_readyport)
	{
		const char *r = " -r ";
		const char *a = (const char *)cfg_readyport;
		while (*r && n < (int)sizeof(cmd) - 2) cmd[n++] = *r++;
		while (*a && n < (int)sizeof(cmd) - 2) cmd[n++] = *a++;
	}
	cmd[n] = '\0';

	nil_in  = Open((CONST_STRPTR)"NIL:", MODE_OLDFILE);
	nil_out = Open((CONST_STRPTR)"NIL:", MODE_NEWFILE);

	systags[0].ti_Tag = SYS_Input;  systags[0].ti_Data = (IPTR)nil_in;
	systags[1].ti_Tag = SYS_Output; systags[1].ti_Data = (IPTR)nil_out;
	systags[2].ti_Tag = SYS_Asynch; systags[2].ti_Data = (IPTR)TRUE;
	systags[3].ti_Tag = TAG_DONE;   systags[3].ti_Data = 0;

	return SystemTagList((CONST_STRPTR)cmd, systags) != -1;
}

int main(int argc, char **argv)
{
	struct Process *me;
	int detach_me = 0;
	int i;

	me = (struct Process *)FindTask(NULL);
	if (me)
		me->pr_WindowPtr = (APTR)-1;

	for (i = 1; i < argc; i++)
	{
		if (argv[i][0] == '-' && argv[i][1] == 'p' && i + 1 < argc)
		{
			LONG v = 0;
			CONST_STRPTR q = (CONST_STRPTR)argv[++i];
			while (*q >= '0' && *q <= '9') v = v * 10 + (*q++ - '0');
			if (v > 0) cfg_port = v;
		}
		else if (argv[i][0] == '-' && argv[i][1] == 'b' && i + 1 < argc)
		{
			cfg_bind = (CONST_STRPTR)argv[++i];
		}
		else if (argv[i][0] == '-' && argv[i][1] == 'n' && i + 1 < argc)
		{
			LONG v = 0;
			CONST_STRPTR q = (CONST_STRPTR)argv[++i];
			while (*q >= '0' && *q <= '9') v = v * 10 + (*q++ - '0');
			cfg_netwait = v;
		}
		else if (argv[i][0] == '-' && argv[i][1] == 'd')
		{
			detach_me = 1;
		}
		else if (argv[i][0] == '-' && argv[i][1] == 'a')
		{
			/*
			 * -a used to disable authentication. It is gone, and
			 * saying so matters more than ignoring it would: a
			 * script carrying the old flag otherwise gets a daemon
			 * that behaves differently from the one it asked for,
			 * with nothing anywhere to say why. Refuse rather than
			 * start, so the difference cannot pass unnoticed.
			 */
			say("telnetd: -a (disable authentication) no longer exists.\n");
			say("telnetd: this build cannot serve an unauthenticated shell.\n");
			say("telnetd: use an account with a password set in Preferences.\n");
			return RETURN_ERROR;
		}
		else if (argv[i][0] == '-' && argv[i][1] == 'r' && i + 1 < argc)
		{
			cfg_readyport = (CONST_STRPTR)argv[++i];
		}
		else if (argv[i][0] == '-' && argv[i][1] == 'l' && i + 1 < argc)
		{
			cfg_logfile = (CONST_STRPTR)argv[++i];
		}
		else if (argv[i][0] == '-' && argv[i][1] == 't' && i + 1 < argc)
		{
			LONG v = 0;
			CONST_STRPTR q = (CONST_STRPTR)argv[++i];
			while (*q >= '0' && *q <= '9') v = v * 10 + (*q++ - '0');
			cfg_wait = v;
		}
	}

	if (detach_me)
	{
		/*
		 * The log is opened by the CHILD, not here: this process is
		 * about to exit and a file handle it owns would go with it.
		 */
		CONST_STRPTR self = (argc > 0 && argv[0] && argv[0][0])
		                    ? (CONST_STRPTR)argv[0]
		                    : (CONST_STRPTR)"telnetd";

		char rname[40];
		struct MsgPort *ready;
		int waited, ok = 0;

		ready_portname(rname, (long)sizeof(rname));

		ready = CreateMsgPort();
		if (ready == NULL)
		{
			say("telnetd: no message port for the ready handshake\n");
			return RETURN_FAIL;
		}
		ready->mp_Node.ln_Name = rname;
		ready->mp_Node.ln_Pri  = 0;
		AddPort(ready);

		cfg_readyport = (CONST_STRPTR)rname;

		if (!detach(self, argc, argv))
		{
			say("telnetd: could not detach\n");
			RemPort(ready);
			DeleteMsgPort(ready);
			return RETURN_FAIL;
		}

		/*
		 * Wait for the child to reach listen().
		 *
		 * This was a flat ten seconds, which stopped being right the
		 * moment -n existed: the child may spend up to cfg_netwait
		 * seconds waiting for the network stack BEFORE it binds, and
		 * the two numbers did not know about each other. At boot, with
		 * -n 60 and a stack that took twelve seconds to appear, the
		 * parent gave up and announced "started but never began
		 * listening -- port already in use?" while the daemon came up
		 * perfectly well a moment later. Both halves of that sentence
		 * were false, and reporting a working daemon as a failed one is
		 * the same dishonesty this handshake exists to prevent, just
		 * pointing the other way.
		 *
		 * The parent parsed the same argv, so it already knows the
		 * number. Ten seconds of margin on top, for the bind and listen
		 * themselves.
		 */
		{
			int limit = (int)(cfg_netwait + 10) * 5;	/* 1/5s ticks */

			for (waited = 0; waited < limit && !ok; waited++)
			{
				Delay(10);	/* 1/5 second */
				if (GetMsg(ready) != NULL)
					ok = 1;
			}
		}

		RemPort(ready);
		DeleteMsgPort(ready);

		if (ok)
		{
			say("telnetd: detached and listening\n");
			return RETURN_OK;
		}

		/*
		 * Distinct from a failure to create the process, so a supervisor
		 * can tell "someone beat me to this port, stand down" from
		 * "something is wrong, raise an alarm".
		 */
		say("telnetd: started but never began listening.\n");
		say("telnetd: the port may be in use, or the network stack may not be up\n");
		say("telnetd: (see -n). The child's own log, if -l was given, will say which.\n");
		return RETURN_ERROR;
	}

	daemon_main();
	return RETURN_OK;
}

static void daemon_main(void)
{
	struct sockaddr_in addr;
	struct Process *me;
	LONG listener = -1;	/* MUST be initialised: `done:` tests it */
	LONG yes = 1;
	LONG port_no = cfg_port;
	LONG wait_secs = cfg_wait;
	LONG session_no = 0;
	CONST_STRPTR bind_addr = cfg_bind;
	int i;

	me = (struct Process *)FindTask(NULL);
	if (me)
		me->pr_WindowPtr = (APTR)-1;

	for (i = 0; i < MAX_SESSIONS; i++)
		sessions[i].sock = -1;

	log_enabled = 1;	/* from here the daemon owns the log file */

	/*
	 * Say what we were asked to do, before doing any of it.
	 *
	 * The boot failure that prompted this left a THIRTY-NINE BYTE log whose
	 * single line was either "waiting for the network stack" or "cannot open
	 * bsdsocket.library" -- two different failures whose messages happen to
	 * be the same length, so the file recorded that something went wrong
	 * without recording which thing. A log that cannot distinguish its own
	 * failure modes is decoration.
	 *
	 * These lines also prove the arguments arrived: the child is launched
	 * from a command line this program rebuilt, and "-n was silently
	 * dropped" and "the stack really was absent" look identical from
	 * outside.
	 */
	say("telnetd: start\n");
	say_num("telnetd: port = ", cfg_port);
	say_num("telnetd: network wait secs = ", cfg_netwait);
	say_num("telnetd: first-connection timeout secs = ", cfg_wait);

	/*
	 * Wait for the network stack, if asked to.
	 *
	 * Started from a boot script there is no guarantee the stack is up yet,
	 * and the failure is a race: it works when you test it and fails on the
	 * one boot that matters. -n says how long to keep asking. It is opt-in
	 * and defaults to nothing, so an ordinary launch still fails at once
	 * rather than hanging for a minute on a machine with no networking.
	 *
	 * Deliberately only around OpenLibrary. bind() failing is a DIFFERENT
	 * fact -- the port is taken -- and retrying that would turn "somebody
	 * else is already listening" into a long silence.
	 */
	{
		LONG waited = 0;

		/*
		 * A heartbeat, because the interesting failure happens INSIDE
		 * this loop.
		 *
		 * At boot the child logged that it was waiting and was then
		 * simply gone -- no success line, no give-up line, no process.
		 * A single line at the start cannot distinguish "died after two
		 * seconds" from "waited the full minute and then died", and
		 * those point at completely different things. So it says how far
		 * it got, and the last line standing is the answer.
		 */
		for (;;)
		{
			SocketBase = OpenLibrary("bsdsocket.library", 4);
			if (SocketBase != NULL || waited >= cfg_netwait)
				break;
			if (waited == 0)
				say("telnetd: waiting for the network stack\n");
			else if ((waited % 5) == 0)
				say_num("telnetd: still waiting, seconds = ", waited);
			Delay(50);	/* one second: 50 ticks */
			waited++;
		}

		say_num("telnetd: network wait finished, seconds = ", waited);

		if (SocketBase == NULL)
		{
			say("telnetd: cannot open bsdsocket.library\n");
			say_num("telnetd: gave up after seconds = ", waited);
			goto done;
		}
		if (waited > 0)
			say_num("telnetd: network stack appeared after seconds = ", waited);
	}

	UserGroupBase = OpenLibrary("usergroup.library", 0);
	if (UserGroupBase != NULL)
	{
		/*
		 * A context must exist before any database call. Without it
		 * getpwnam() returns NULL for every account whatever the
		 * database holds -- which cost most of an evening, read first as
		 * an empty store, then a malformed passwd line, then a broken
		 * netinfo.device. None of those were it.
		 */
		struct TagItem tags[1];
		tags[0].ti_Tag = TAG_DONE;
		tags[0].ti_Data = 0;
		ug_SetupContextTagList((CONST_STRPTR)"telnetd", tags);
	}
	if (UserGroupBase == NULL)
	{
		/* No database means no way to check a password, and there is no
		 * longer any flag that could talk us past that. Refusing to
		 * start is the only safe answer. */
		say("telnetd: usergroup.library not available, so no login can be checked.\n");
		say("telnetd: refusing to start rather than serve unauthenticated shells.\n");
		CloseLibrary(SocketBase);
		SocketBase = NULL;
		goto done;
	}

	/*
	 * RETRY BIND, rather than wait for a proxy and then bind once.
	 *
	 * -n used to wait for OpenLibrary("bsdsocket.library") to succeed and
	 * then bind exactly once. At boot that wait was satisfied INSTANTLY --
	 * measured: not one heartbeat line -- because the library is loadable
	 * almost immediately while the stack behind it is still coming up. So
	 * the readiness test passed, bind ran into a stack that was not ready,
	 * and the daemon exited. Waiting on a proxy and then performing the real
	 * operation once is the bug; bind is the thing we actually need, and it
	 * is its own readiness test.
	 *
	 * The message was worse than the bug. It said "port in use?" for ANY
	 * bind failure -- mapping every cause onto the most familiar one -- and
	 * cost somebody a hunt for a collision that did not exist. It now
	 * reports the errno and says nothing it does not know. Diagnosis by
	 * reading the log properly rather than inferring from the symptom.
	 *
	 * With no -n this is still exactly one attempt, so starting on a port
	 * somebody else holds still fails at once.
	 */
	{
		LONG waited = 0;
		LONG e = 0;

		for (;;)
		{
			listener = socket(AF_INET, SOCK_STREAM, 0);
			if (listener < 0)
			{
				e = Errno();
			}
			else
			{
				setsockopt(listener, SOL_SOCKET, SO_REUSEADDR,
				           (APTR)&yes, sizeof(yes));

				memset(&addr, 0, sizeof(addr));
				addr.sin_family = AF_INET;
				addr.sin_port   = htons((unsigned short)port_no);
				addr.sin_addr.s_addr =
					bind_addr ? inet_addr(bind_addr) : INADDR_ANY;

				if (bind(listener, (struct sockaddr *)&addr,
				         sizeof(addr)) >= 0)
					break;

				e = Errno();

				/* A fresh socket each attempt: a stack that
				 * refused one may have marked it. */
				CloseSocket(listener);
				listener = -1;
			}

			if (waited >= cfg_netwait)
			{
				say_num("telnetd: cannot bind port ", port_no);
				say_num("telnetd: last errno was ", e);
				say_num("telnetd: after waiting seconds = ", waited);
				say("telnetd: errno 48 is the port already taken; anything\n");
				say("telnetd: else usually means the stack is not ready.\n");
				goto done;
			}

			if (waited == 0 || (waited % 5) == 0)
				say_num("telnetd: bind not ready, errno = ", e);

			Delay(50);	/* one second */
			waited++;
		}

		if (waited > 0)
			say_num("telnetd: bound after seconds = ", waited);
	}

	/* A real backlog. With a backlog of 1 the kernel completed handshakes
	 * for callers this process could not yet reach, so they looked
	 * connected and received nothing. */
	if (listen(listener, MAX_SESSIONS + 2) < 0)
	{
		say("telnetd: listen() failed\n");
		CloseSocket(listener);
		listener = -1;
		goto done;
	}

	/*
	 * Tell the launcher we are up -- only now, with bind() and listen()
	 * both behind us, so the signal means "serving" and not "started".
	 */
	if (cfg_readyport)
	{
		struct MsgPort *parent;

		Forbid();
		parent = FindPort(cfg_readyport);
		if (parent)
		{
			static struct Message ready;
			ready.mn_Node.ln_Type = NT_MESSAGE;
			ready.mn_ReplyPort    = NULL;
			ready.mn_Length       = sizeof(ready);
			PutMsg(parent, &ready);
		}
		Permit();
	}

	say("telnetd: listening on ");
	say(bind_addr ? bind_addr : (CONST_STRPTR)"all interfaces");
	say_num(" port ", port_no);
	say_num("telnetd: concurrent sessions = ", MAX_SESSIONS);

	/*
	 * ONE LOOP, EVERY SESSION.
	 *
	 * WaitSelect takes both a socket set and an Exec signal mask, so a
	 * single wait covers the listener, every live session's socket, and
	 * every session's console message port at once. That is what makes a
	 * single process serve several sessions without threads -- which suits
	 * a machine where SMP does not work and every session is I/O bound.
	 */
	for (;;)
	{
		fd_set rd, wr;
		struct timeval tv;
		LONG sigs = SIGBREAKF_CTRL_C;
		LONG nready, maxfd = listener;
		int active = 0, deadline_pending = 0;

		FD_ZERO(&rd);
		FD_ZERO(&wr);
		FD_SET(listener, &rd);

		for (i = 0; i < MAX_SESSIONS; i++)
		{
			struct Session *s = &sessions[i];
			if (!s->in_use)
				continue;
			active++;
			if (s->sock >= 0)
			{
				/* Stop reading when there is nowhere to put it.
				 * TCP then does the flow control for us, rather
				 * than us parsing bytes and dropping them. */
				if (!s->peer_gone && s->in_len < INBUF_SIZE)
					FD_SET(s->sock, &rd);
				/* Never watch a dead socket for writability: it
				 * reports ready every time and spins the loop. */
				if (!s->peer_gone && net_pending(s) > 0)
					FD_SET(s->sock, &wr);
				if (s->sock > maxfd) maxfd = s->sock;
			}
			/* Anything with a deadline on it -- a login not yet
			 * completed, a drain not yet finished -- needs the wait
			 * kept short enough to reach that deadline. Queued
			 * output does not: the write set already wakes us. */
			if (!s->shell_started || s->peer_gone
			    || !s->con.established)
				deadline_pending++;
			if (s->port)      sigs |= (1UL << s->port->mp_SigBit);
			if (s->replyport) sigs |= (1UL << s->replyport->mp_SigBit);
		}

		for (i = 0; i < MAX_REAPERS; i++)
		{
			if (!reapers[i].in_use || reapers[i].port == NULL)
				continue;
			deadline_pending++;
			sigs |= (1UL << reapers[i].port->mp_SigBit);
		}

		/*
		 * Sleep until something happens -- unless something is winding
		 * down, in which case a deadline has to be checked and the wait
		 * has to be short enough to reach it.
		 */
		if (deadline_pending)
			tv.tv_sec = 1;
		else
			tv.tv_sec = wait_secs > 0 ? wait_secs : 3600;
		tv.tv_usec = 0;

		nready = WaitSelect(maxfd + 1, &rd, &wr, NULL, &tv, (ULONG *)&sigs);

		if (sigs & SIGBREAKF_CTRL_C)
		{
			say("telnetd: interrupted; shutting down\n");
			break;
		}

		/* Service every session; each decides what it can do. */
		for (i = 0; i < MAX_SESSIONS; i++)
		{
			struct Session *s = &sessions[i];
			if (!s->in_use)
				continue;
			if (!s->shell_started && s->phase != PHASE_BYE
			    && now_secs() >= s->login_deadline)
				session_login_timeout(s);

			session_service(s,
			                (nready > 0 && s->sock >= 0
			                 && FD_ISSET(s->sock, &rd)),
			                (nready > 0 && s->sock >= 0
			                 && FD_ISSET(s->sock, &wr)));

			if (session_finished(s)
			    || (session_expired(s) && reaper_available()))
				session_end(s);
		}

		/* Consoles whose clients are gone but whose shells are not. */
		for (i = 0; i < MAX_REAPERS; i++)
			if (reapers[i].in_use)
				reaper_service(&reapers[i]);

		/* A new caller, if there is room for one. */
		if (nready > 0 && FD_ISSET(listener, &rd))
		{
			LONG conn = accept(listener, NULL, NULL);
			if (conn >= 0)
			{
				int slot = -1;
				for (i = 0; i < MAX_SESSIONS; i++)
					if (!sessions[i].in_use) { slot = i; break; }

				if (slot < 0)
				{
					/*
					 * Full. Say so and close, rather than
					 * leaving the caller connected to
					 * silence -- which is what the old
					 * single-session server did to every
					 * second client.
					 */
					static const char busy[] =
						"\r\ntelnetd: too many sessions; try again shortly.\r\n";
					send(conn, (APTR)busy, (LONG)sizeof(busy) - 1, 0);
					CloseSocket(conn);
					say("telnetd: refused a caller, all slots busy\n");
				}
				else if (!session_start(&sessions[slot], conn, session_no++))
				{
					say("telnetd: session failed to start\n");
				}
			}
			continue;
		}

		if (nready == 0 && active == 0 && deadline_pending == 0 && wait_secs > 0)
		{
			say("telnetd: no connection within the timeout; exiting\n");
			break;
		}
	}

	for (i = 0; i < MAX_SESSIONS; i++)
		if (sessions[i].in_use)
			session_end(&sessions[i]);

	/*
	 * Every port left over has mp_SigTask pointing at this process, which
	 * is about to stop existing. PA_IGNORE makes PutMsg enqueue and return
	 * without signalling anyone, so a Shell that outlives us blocks
	 * harmlessly instead of signalling freed memory -- the difference
	 * between a stranded process and a dead machine.
	 */
	for (i = 0; i < MAX_REAPERS; i++)
		if (reapers[i].in_use && reapers[i].port)
			reapers[i].port->mp_Flags = PA_IGNORE;
	for (i = 0; i < port_pool_n; i++)
		if (port_pool[i])
			port_pool[i]->mp_Flags = PA_IGNORE;

	CloseSocket(listener);
	listener = -1;

done:
	/*
	 * ONE EXIT, because the log has to be closed on every path.
	 *
	 * Each failure used to `return` straight out, leaving the log file
	 * handle open in a process that then ceased to exist. On a platform
	 * that reclaims nothing, that is a lock held by nobody until the next
	 * reboot -- so the boot that failed made its own explanation
	 * unreadable, and the only thing that could say why refused to open.
	 * Reported from the far end by somebody who had a silent port, a
	 * locked 39-byte log and no way to see inside it.
	 *
	 * A failure must never take its reason with it.
	 */
	/*
	 * Order matters, and so does that initialiser.
	 *
	 * `listener` was uninitialised. The two paths that fail before a socket
	 * exists -- bsdsocket.library never appearing, usergroup.library missing
	 * -- arrive here with SocketBase NULL and whatever was in that stack
	 * slot deciding whether we then call CloseSocket() through a NULL
	 * library base. On this platform that is not an error return, it is a
	 * dead machine: a jump through address zero minus an LVO.
	 *
	 * It was introduced by the commit that added this label, and the path it
	 * sits on is exactly the one a boot with a late network stack takes --
	 * so the code written to diagnose a silent boot failure could itself
	 * have caused one, with the same symptoms. Found in review before it
	 * ever ran that path.
	 */
	if (SocketBase && listener >= 0) CloseSocket(listener);
	if (UserGroupBase)      CloseLibrary(UserGroupBase);
	if (SocketBase)         CloseLibrary(SocketBase);
	say("telnetd: exit\n");
}
