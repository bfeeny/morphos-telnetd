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
 * Development bypass for authentication.
 *
 * OFF by default, and it has to stay that way: the whole point of the policy is
 * that a MorphOS account with no password refuses remote login, and a bypass
 * that could be reached by accident would undo it. It exists because the
 * machine's owner is not always present to type a password, and it announces
 * itself in the log AND to the connecting client so it can never be running
 * unnoticed.
 */
static int allow_no_auth = 0;

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

#define DEFAULT_PORT   23
#define MOUNT_NAME     "TELCON"
#define SHELL_COMMAND  "NewShell " MOUNT_NAME ":"
#define INBUF_SIZE     4096
#define MAX_DEFERRED   8

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
 * How long a session may sit doing nothing before we wind it down.
 *
 * Deliberately generous. Unix telnetd has no idle limit at all -- an idle
 * shell is the normal state of a remote login, not a fault -- so this exists
 * only as a safety net against a session nobody is attached to any more, not
 * as a policy about how fast a person should type. Two consecutive intervals
 * are required, so the real limit is twice this.
 */
#define SESSION_IDLE_SECS 300

/* Time to complete a login. Matches the usual telnetd/login convention. */
#define LOGIN_TIMEOUT_SECS 60

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


/* ------------------------------------------------------------------ */

/*
 * Diagnostics go to a file when -l is given.
 *
 * stdout is useless when this runs detached or when the job that launched it
 * times out: the output goes with it, and a wedge becomes unexplainable. The
 * probe learned the same lesson -- instrumentation has to outlive the failure
 * it is describing.
 */
static BPTR logfh = 0;

static void say(CONST_STRPTR s)
{
	BPTR out = logfh ? logfh : Output();
	if (out)
	{
		Write(out, (APTR)s, (LONG)strlen(s));
		if (logfh)
			Flush(logfh);	/* a crash must not lose the last line */
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
	{
		BPTR out = logfh ? logfh : Output();
		if (out)
		{
			Write(out, p, (LONG)(buf + sizeof(buf) - p));
			if (logfh)
				Flush(logfh);
		}
	}
}

/* ------------------------------------------------------------------ */
/* Callbacks: telnet <-> console                                       */

static void net_out(void *ctx, const unsigned char *buf, long len)
{
	struct Session *s = (struct Session *)ctx;

	if (s->sock >= 0 && len > 0)
		send(s->sock, (APTR)buf, len, 0);
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

/*
 * Read one line from the client, with a deadline.
 *
 * `echo` false is used for the password: we told the client WILL ECHO, so it
 * sends us characters and expects US to echo them. Simply not echoing is what
 * hides the password -- there is no separate "turn off echo" needed, because we
 * were never not in control of it.
 */
static int read_line(struct Session *s, char *out, long max, int echo, LONG secs)
{
	long n = 0;

	out[0] = '\0';

	for (;;)
	{
		fd_set rd;
		struct timeval tv;
		LONG sigs = SIGBREAKF_CTRL_C;
		unsigned char raw[256], clean[256];
		LONG got, i, cnt;

		FD_ZERO(&rd);
		FD_SET(s->sock, &rd);
		tv.tv_sec = secs; tv.tv_usec = 0;

		if (WaitSelect(s->sock + 1, &rd, NULL, NULL, &tv, (ULONG *)&sigs) <= 0)
			return 0;	/* timed out, or interrupted */
		if (sigs & SIGBREAKF_CTRL_C)
			return 0;
		if (!FD_ISSET(s->sock, &rd))
			continue;

		got = recv(s->sock, raw, sizeof(raw), 0);
		if (got <= 0)
			return 0;	/* hung up mid-login */

		cnt = telnet_input(&s->tn, raw, got, clean, sizeof(clean));

		for (i = 0; i < cnt; i++)
		{
			unsigned char c = clean[i];

			if (c == '\r' || c == '\n')
			{
				if (n == 0 && c == '\n')
					continue;	/* bare LF after CR */
				out[n] = '\0';
				net_write_str(s, (CONST_STRPTR)"\r\n");
				return 1;
			}
			if (c == 8 || c == 127)		/* backspace / delete */
			{
				if (n > 0)
				{
					n--;
					if (echo)
						net_write_str(s, (CONST_STRPTR)"\b \b");
				}
				continue;
			}
			if (c < 32 || c > 126)
				continue;		/* ignore control bytes */

			if (n < max - 1)
			{
				out[n++] = (char)c;
				if (echo)
					telnet_output(&s->tn, &c, 1);
			}
		}
	}
}

/*
 * Authenticate, using the system's own user database.
 *
 * The daemon never stores a credential: getpwnam() gives us a salted hash,
 * ug_GetSalt() gives us its salt, and crypt() turns what was typed into
 * something comparable. The typed password lives only in a stack buffer, which
 * is wiped before returning.
 */
static int authenticate(struct Session *s)
{
	char user[64], pass[128];
	struct passwd *pw;
	char salt[64];
	enum AuthResult res;
	int i;

	if (allow_no_auth)
	{
		say("telnetd: WARNING -- authentication bypassed (-allow-no-auth)\n");
		net_write_str(s, (CONST_STRPTR)
			"\r\n*** WARNING: this telnetd is running with authentication DISABLED ***\r\n\r\n");
		return 1;
	}

	if (UserGroupBase == NULL)
	{
		say("telnetd: usergroup.library unavailable; refusing all logins\n");
		net_write_str(s, (CONST_STRPTR)"Authentication unavailable.\r\n");
		return 0;
	}

	net_write_str(s, (CONST_STRPTR)"\r\nMorphOS telnetd\r\n\r\nlogin: ");
	if (!read_line(s, user, (long)sizeof(user), 1, LOGIN_TIMEOUT_SECS) || user[0] == '\0')
		return 0;

	net_write_str(s, (CONST_STRPTR)"password: ");
	if (!read_line(s, pass, (long)sizeof(pass), 0, LOGIN_TIMEOUT_SECS))
		return 0;

	pw = getpwnam((STRPTR)user);
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
		                  (pw && pass[0])
		                      ? (const char *)crypt((STRPTR)pass, (STRPTR)saltp)
		                      : NULL);
	}

	/* Wipe the typed password as soon as it has been hashed. */
	for (i = 0; i < (int)sizeof(pass); i++)
		pass[i] = 0;

	say("telnetd: login '");
	say((CONST_STRPTR)user);
	say("' -> ");
	say((CONST_STRPTR)auth_result_name(res));
	say("\n");

	if (res != AUTH_OK)
	{
		/* One message for every failure: never tell a stranger whether
		 * the account exists or merely has no password. */
		net_write_str(s, (CONST_STRPTR)"\r\nLogin incorrect.\r\n");
		return 0;
	}

	net_write_str(s, (CONST_STRPTR)"\r\n");
	return 1;
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

		if (pkt->dp_Type == ACTION_READ || pkt->dp_Type == ACTION_WRITE)
		{
			bufarg = (void *)pkt->dp_Arg2;
			len    = pkt->dp_Arg3;
		}

		r = console_dispatch(con, pkt->dp_Type, pkt->dp_Arg1,
		                     pkt->dp_Arg2, bufarg, len);

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
	if (s->helper_done && console_session_finished(&s->con))
		port_put(s->port);
	else if (!reaper_adopt(s))
		say("telnetd: no reaper free -- abandoning a console port\n");
	s->port = NULL;

	if (s->helper_done)
	{
		if (s->replyport) DeleteMsgPort(s->replyport);
		if (s->sm)        FreeVec(s->sm);
	}
	s->replyport = NULL;
	s->sm = NULL;

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
	return s->helper_done && console_session_finished(&s->con);
}

static int session_expired(struct Session *s)
{
	return s->peer_gone
	    && s->drain_deadline != 0
	    && now_secs() >= s->drain_deadline;
}

static int session_start(struct Session *s, LONG sock, LONG session_no)
{
	struct TagItem proctags[6];
	LONG yes = 1;

	memset(s, 0, sizeof(*s));
	s->in_use = 1;
	s->sock   = sock;
	s->ndef   = 0;

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

	/* The telnet layer must exist before authentication: the login dialogue
	 * is carried over it. */
	telnet_init(&s->tn, net_out, net_size, s);
	console_init(&s->con, shell_read, shell_write, s, 2, 0);
	telnet_start(&s->tn);

	if (!authenticate(s))
	{
		say("telnetd: login failed; closing\n");
		goto fail;
	}

	s->devnode = MakeDosEntry((CONST_STRPTR)s->mount_name, DLT_DEVICE);
	if (s->devnode == NULL) { say("telnetd: MakeDosEntry failed\n"); goto fail; }
	s->devnode->dol_Task = s->port;
	if (!AddDosEntry(s->devnode))
	{
		/* Tell the client. A connection that is accepted and then
		 * silently dropped is the worst outcome available -- the caller
		 * cannot tell it from a hang. */
		static const char clash[] =
			"\r\ntelnetd: could not create a console for this session.\r\n";
		say("telnetd: mount name already in use: ");
		say((CONST_STRPTR)s->mount_name);
		say("\n");
		send(s->sock, (APTR)clash, (LONG)sizeof(clash) - 1, 0);
		FreeDosEntry(s->devnode);
		s->devnode = NULL;
		goto fail;
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

	IoctlSocket(s->sock, TD_FIONBIO, (APTR)&yes);

	proctags[0].ti_Tag = NP_CodeType;   proctags[0].ti_Data = CODETYPE_PPC;
	proctags[1].ti_Tag = NP_Entry;      proctags[1].ti_Data = (IPTR)spawn_helper;
	proctags[2].ti_Tag = NP_StartupMsg; proctags[2].ti_Data = (IPTR)s->sm;
	proctags[3].ti_Tag = NP_Name;       proctags[3].ti_Data = (IPTR)"telnetd session";
	proctags[4].ti_Tag = NP_WindowPtr;  proctags[4].ti_Data = (IPTR)-1;
	proctags[5].ti_Tag = TAG_DONE;      proctags[5].ti_Data = 0;

	if (CreateNewProc(proctags) == NULL)
	{
		say("telnetd: could not start the shell\n");
		goto fail;
	}

	say("telnetd: session on ");
	say((CONST_STRPTR)s->mount_name);
	say(":\n");
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

/* One slice of work: whatever this session can do without blocking. */
static void session_service(struct Session *s, int readable)
{
	long i;

	if (s->sock >= 0 && readable)
	{
		unsigned char raw[1024];
		LONG got = recv(s->sock, raw, sizeof(raw), 0);

		if (got > 0)
		{
			long room = INBUF_SIZE - s->in_len;
			long n = telnet_input(&s->tn, raw, got, s->in + s->in_len, room);
			s->in_len += n;
		}
		else if (got == 0)
		{
			s->peer_gone      = 1;
			s->drain_deadline = now_secs() + DRAIN_GRACE_SECS;
			console_begin_drain(&s->con);
			say("telnetd: peer closed; draining\n");
		}
		/* got < 0 is EWOULDBLOCK on a non-blocking socket, not a hangup. */
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

	service_port(s->port, &s->con, s->deferred, &s->ndef, MAX_DEFERRED);

	while (GetMsg(s->replyport) != NULL)
	{
		s->helper_done = 1;
		say_num("telnetd: helper finished, SystemTagList rc = ", s->sm->rc);
	}
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
		else if (argv[i][0] == '-' && argv[i][1] == 'a')
		{
			allow_no_auth = 1;
		}
		else if (argv[i][0] == '-' && argv[i][1] == 'd')
		{
			detach_me = 1;
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

		/* Up to ten seconds for the child to reach listen(). */
		for (waited = 0; waited < 50 && !ok; waited++)
		{
			Delay(10);	/* 1/5 second */
			if (GetMsg(ready) != NULL)
				ok = 1;
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
		say("telnetd: started but never began listening -- port already in use?\n");
		return RETURN_ERROR;
	}

	daemon_main();
	return RETURN_OK;
}

static void daemon_main(void)
{
	struct sockaddr_in addr;
	struct Process *me;
	LONG listener;
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

	if (cfg_logfile)
		logfh = Open(cfg_logfile, MODE_NEWFILE);

	SocketBase = OpenLibrary("bsdsocket.library", 4);
	if (SocketBase == NULL)
	{
		say("telnetd: cannot open bsdsocket.library\n");
		return;
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
	if (UserGroupBase == NULL && !allow_no_auth)
	{
		say("telnetd: usergroup.library not available and no bypass given.\n");
		say("telnetd: refusing to start rather than serve unauthenticated shells.\n");
		CloseLibrary(SocketBase);
		return;
	}

	listener = socket(AF_INET, SOCK_STREAM, 0);
	if (listener < 0)
	{
		say("telnetd: socket() failed\n");
		CloseLibrary(SocketBase);
		return;
	}

	setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, (APTR)&yes, sizeof(yes));

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port   = htons((unsigned short)port_no);
	addr.sin_addr.s_addr = bind_addr ? inet_addr(bind_addr) : INADDR_ANY;

	if (bind(listener, (struct sockaddr *)&addr, sizeof(addr)) < 0)
	{
		say("telnetd: bind() failed -- port in use?\n");
		CloseSocket(listener);
		CloseLibrary(SocketBase);
		return;
	}

	/* A real backlog. With a backlog of 1 the kernel completed handshakes
	 * for callers this process could not yet reach, so they looked
	 * connected and received nothing. */
	if (listen(listener, MAX_SESSIONS + 2) < 0)
	{
		say("telnetd: listen() failed\n");
		CloseSocket(listener);
		CloseLibrary(SocketBase);
		return;
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
	if (allow_no_auth)
		say("telnetd: *** AUTHENTICATION DISABLED (-allow-no-auth) ***\n");

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
		fd_set rd;
		struct timeval tv;
		LONG sigs = SIGBREAKF_CTRL_C;
		LONG nready, maxfd = listener;
		int active = 0, winding_down = 0;

		FD_ZERO(&rd);
		FD_SET(listener, &rd);

		for (i = 0; i < MAX_SESSIONS; i++)
		{
			struct Session *s = &sessions[i];
			if (!s->in_use)
				continue;
			active++;
			if (s->sock >= 0 && !s->peer_gone)
			{
				FD_SET(s->sock, &rd);
				if (s->sock > maxfd) maxfd = s->sock;
			}
			if (s->peer_gone) winding_down++;
			if (s->port)      sigs |= (1UL << s->port->mp_SigBit);
			if (s->replyport) sigs |= (1UL << s->replyport->mp_SigBit);
		}

		for (i = 0; i < MAX_REAPERS; i++)
		{
			if (!reapers[i].in_use || reapers[i].port == NULL)
				continue;
			winding_down++;
			sigs |= (1UL << reapers[i].port->mp_SigBit);
		}

		/*
		 * Sleep until something happens -- unless something is winding
		 * down, in which case a deadline has to be checked and the wait
		 * has to be short enough to reach it.
		 */
		if (winding_down)
			tv.tv_sec = 1;
		else
			tv.tv_sec = wait_secs > 0 ? wait_secs : 3600;
		tv.tv_usec = 0;

		nready = WaitSelect(maxfd + 1, &rd, NULL, NULL, &tv, (ULONG *)&sigs);

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
			session_service(s, (nready > 0 && s->sock >= 0
			                    && FD_ISSET(s->sock, &rd)));
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

		if (nready == 0 && active == 0 && winding_down == 0 && wait_secs > 0)
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
	if (UserGroupBase) CloseLibrary(UserGroupBase);
	CloseLibrary(SocketBase);
	if (logfh) { say("telnetd: exit\n"); Close(logfh); logfh = 0; }
}
