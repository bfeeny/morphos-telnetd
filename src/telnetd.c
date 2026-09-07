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

#include "console_handler.h"
#include "telnet.h"

struct Library *SocketBase = NULL;

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
#define SESSION_IDLE_SECS 30	/* no packets for this long -> wind the session down */

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
};

struct Session
{
	LONG               sock;
	struct TelnetState tn;
	struct ConsoleState con;

	/* Bytes from the network, already stripped of telnet commands. */
	unsigned char in[INBUF_SIZE];
	long          in_len;
	long          in_pos;
	int           peer_gone;
};

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

	sm->rc = SystemTagList((CONST_STRPTR)SHELL_COMMAND, systags);

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

static void run_session(LONG sock)
{
	struct Session     *s;
	struct MsgPort     *port = NULL, *replyport = NULL;
	struct SpawnMsg    *sm = NULL;
	struct FileHandle  *fh_in = NULL, *fh_out = NULL;
	struct DosList     *devnode = NULL;
	struct DosPacket   *deferred[MAX_DEFERRED];
	long                ndef = 0;
	struct TagItem      proctags[6];
	int                 helper_done = 0;
	int                 idle_ticks = 0;
	LONG                yes = 1;

	s = AllocVec(sizeof(struct Session), MEMF_PUBLIC | MEMF_CLEAR);
	if (s == NULL) { say("telnetd: out of memory\n"); return; }
	s->sock = sock;

	port      = CreateMsgPort();
	replyport = CreateMsgPort();
	sm        = AllocVec(sizeof(struct SpawnMsg), MEMF_PUBLIC | MEMF_CLEAR);
	fh_in     = port ? make_handle(port, MODE_OLDFILE, HANDLE_IN)  : NULL;
	fh_out    = port ? make_handle(port, MODE_NEWFILE, HANDLE_OUT) : NULL;

	if (!port || !replyport || !sm || !fh_in || !fh_out)
	{
		say("telnetd: session setup failed\n");
		goto cleanup_early;
	}

	devnode = MakeDosEntry((CONST_STRPTR)MOUNT_NAME, DLT_DEVICE);
	if (devnode == NULL) { say("telnetd: MakeDosEntry failed\n"); goto cleanup_early; }
	devnode->dol_Task = port;
	if (!AddDosEntry(devnode))
	{
		say("telnetd: " MOUNT_NAME ": already in use\n");
		FreeDosEntry(devnode); devnode = NULL;
		goto cleanup_early;
	}

	telnet_init(&s->tn, net_out, net_size, s);
	console_init(&s->con, shell_read, shell_write, s, 2, 0);
	telnet_start(&s->tn);

	/* Non-blocking: WaitSelect tells us when to read, and a blocking recv
	 * inside the packet loop would stall the Shell. */
	IoctlSocket(sock, TD_FIONBIO, (APTR)&yes);

	sm->msg.mn_Node.ln_Type = NT_MESSAGE;
	sm->msg.mn_ReplyPort    = replyport;
	sm->msg.mn_Length       = sizeof(struct SpawnMsg);
	sm->input               = MKBADDR(fh_in);
	sm->output              = MKBADDR(fh_out);
	sm->console_port        = (APTR)port;

	proctags[0].ti_Tag = NP_CodeType;   proctags[0].ti_Data = CODETYPE_PPC;
	proctags[1].ti_Tag = NP_Entry;      proctags[1].ti_Data = (IPTR)spawn_helper;
	proctags[2].ti_Tag = NP_StartupMsg; proctags[2].ti_Data = (IPTR)sm;
	proctags[3].ti_Tag = NP_Name;       proctags[3].ti_Data = (IPTR)"telnetd session";
	proctags[4].ti_Tag = NP_WindowPtr;  proctags[4].ti_Data = (IPTR)-1;
	proctags[5].ti_Tag = TAG_DONE;      proctags[5].ti_Data = 0;

	if (CreateNewProc(proctags) == NULL)
	{
		say("telnetd: could not start the shell\n");
		goto cleanup_mounted;
	}

	say("telnetd: mounted " MOUNT_NAME ": and started helper\n");
	say("telnetd: shell command = " SHELL_COMMAND "\n");

	while (!helper_done || !console_session_finished(&s->con))
	{
		fd_set rd;
		LONG   sigs = (1UL << port->mp_SigBit)
		            | (1UL << replyport->mp_SigBit)
		            | SIGBREAKF_CTRL_C;
		struct Message *msg;
		struct timeval tv;
		long i;
		LONG before = s->con.packets;

		FD_ZERO(&rd);
		if (s->sock >= 0 && !s->peer_gone)
			FD_SET(s->sock, &rd);

		/*
		 * One wait, both worlds: sockets and Exec signals together --
		 * and a timeout, so a session that stops making progress ends
		 * itself instead of parking forever holding a mount and a port.
		 */
		tv.tv_sec  = SESSION_IDLE_SECS;
		tv.tv_usec = 0;
		WaitSelect(s->sock + 1, &rd, NULL, NULL, &tv, (ULONG *)&sigs);

		if (sigs & SIGBREAKF_CTRL_C)
			console_begin_drain(&s->con);

		/* --- network -> shell --- */
		if (s->sock >= 0 && FD_ISSET(s->sock, &rd))
		{
			unsigned char raw[1024];
			LONG got = recv(s->sock, raw, sizeof(raw), 0);

			if (got > 0)
			{
				long room = INBUF_SIZE - s->in_len;
				long n = telnet_input(&s->tn, raw, got,
				                      s->in + s->in_len, room);
				s->in_len += n;
			}
			else if (got == 0)
			{
				s->peer_gone = 1;	/* clean close */
			}
			else
			{
				s->peer_gone = 1;	/* error; treat as hangup */
			}
		}

		/* --- retry anything we held back --- */
		for (i = 0; i < ndef; )
		{
			struct DosPacket *p = deferred[i];
			struct ConsoleReply r =
				console_dispatch(&s->con, p->dp_Type, p->dp_Arg1,
				                 p->dp_Arg2, (void *)p->dp_Arg2,
				                 p->dp_Arg3);

			if (r.defer)
			{
				i++;	/* still nothing for it */
				continue;
			}
			ReplyPkt(p, r.res1, r.res2);
			deferred[i] = deferred[--ndef];
		}

		/* --- shell -> us --- */
		while ((msg = GetMsg(port)) != NULL)
		{
			struct DosPacket *pkt =
				(struct DosPacket *)msg->mn_Node.ln_Name;
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

			say_num("telnetd: packet dp_Type = ", pkt->dp_Type);

			r = console_dispatch(&s->con, pkt->dp_Type, pkt->dp_Arg1,
			                     pkt->dp_Arg2, bufarg, len);

			if (r.defer)
			{
				if (ndef < MAX_DEFERRED)
				{
					deferred[ndef++] = pkt;
					continue;	/* answered later */
				}
				r.res1 = 0;	/* out of room: EOF beats losing it */
			}

			/* Complete an open the way a real handler does:
			 * ahi-handler/main.c:330-331. fh_Interactive is what
			 * makes NewShell accept the stream at all. */
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

		while (GetMsg(replyport) != NULL)
		{
			helper_done = 1;
			/* The helper's exit code is the single most useful fact
			 * when nothing else happens: a shell that never started
			 * and a shell that started and left look identical from
			 * the packet side, which is silence either way. */
			say_num("telnetd: helper finished, SystemTagList rc = ", sm->rc);
		}

		/* Nothing happened at all for a whole timeout: wind it down. */
		say_num("telnetd: loop tick, packets so far = ", s->con.packets);

		if (s->con.packets == before && !(sigs & SIGBREAKF_CTRL_C))
		{
			if (s->con.draining)
			{
				say("telnetd: session idle and not ending; giving up\n");
				break;
			}
			say("telnetd: session idle; draining\n");
			console_begin_drain(&s->con);
		}
	}

	say("telnetd: session ended\n");

	/* Anything still held must be answered, or the Shell waits forever. */
	while (ndef > 0)
		ReplyPkt(deferred[--ndef], 0, 0);

cleanup_mounted:
	if (devnode && RemDosEntry(devnode))
		FreeDosEntry(devnode);

	/*
	 * The message port is deliberately NOT freed. Freeing one a Shell may
	 * still hold a handle to takes down the OS rather than failing politely,
	 * and the only thing that could vouch for it being safe is the packet
	 * accounting -- which is the code under test. A leaked port costs a few
	 * hundred bytes until reboot. Nothing is reclaimed at exit here anyway.
	 */
	if (replyport && helper_done) DeleteMsgPort(replyport);
	if (sm && helper_done)        FreeVec(sm);
	if (s->sock >= 0)             CloseSocket(s->sock);
	FreeVec(s);
	return;

cleanup_early:
	/* Reachable only before any Shell exists, so these really are ours. */
	if (fh_in)     FreeDosObject(DOS_FILEHANDLE, fh_in);
	if (fh_out)    FreeDosObject(DOS_FILEHANDLE, fh_out);
	if (sm)        FreeVec(sm);
	if (replyport) DeleteMsgPort(replyport);
	if (port)      DeleteMsgPort(port);
	if (sock >= 0) CloseSocket(sock);
	FreeVec(s);
}

/* ------------------------------------------------------------------ */

int main(int argc, char **argv)
{
	struct sockaddr_in addr;
	struct Process *me;
	LONG listener, conn;
	LONG yes = 1;
	LONG port_no = DEFAULT_PORT;
	LONG wait_secs = 0;	/* 0 == wait indefinitely */
	CONST_STRPTR bind_addr = NULL;	/* NULL == all interfaces */
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
			if (v > 0) port_no = v;
		}
		else if (argv[i][0] == '-' && argv[i][1] == 'b' && i + 1 < argc)
		{
			bind_addr = (CONST_STRPTR)argv[++i];
		}
		else if (argv[i][0] == '-' && argv[i][1] == 'l' && i + 1 < argc)
		{
			logfh = Open((CONST_STRPTR)argv[++i], MODE_NEWFILE);
		}
		else if (argv[i][0] == '-' && argv[i][1] == 't' && i + 1 < argc)
		{
			LONG v = 0;
			CONST_STRPTR q = (CONST_STRPTR)argv[++i];
			while (*q >= '0' && *q <= '9') v = v * 10 + (*q++ - '0');
			wait_secs = v;
		}
	}

	SocketBase = OpenLibrary("bsdsocket.library", 4);
	if (SocketBase == NULL)
	{
		say("telnetd: cannot open bsdsocket.library\n");
		return RETURN_FAIL;
	}

	listener = socket(AF_INET, SOCK_STREAM, 0);
	if (listener < 0)
	{
		say("telnetd: socket() failed\n");
		CloseLibrary(SocketBase);
		return RETURN_FAIL;
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
		return RETURN_FAIL;
	}

	if (listen(listener, 1) < 0)
	{
		say("telnetd: listen() failed\n");
		CloseSocket(listener);
		CloseLibrary(SocketBase);
		return RETURN_FAIL;
	}

	say("telnetd: listening on ");
	say(bind_addr ? bind_addr : (CONST_STRPTR)"all interfaces");
	say_num(" port ", port_no);
	say("telnetd: one session at a time. CTRL-C to stop.\n");

	/*
	 * Wait for a connection WITHOUT calling accept() blindly.
	 *
	 * A bare accept() parks the process in bsdsocket, where it answers
	 * nothing: not CTRL-C, and not the agent's `bounded` wrapper either,
	 * because a MorphOS process blocked in a library call does not receive
	 * a shell-level kill. The first version did exactly that and had to be
	 * waited out by a 900s watchdog while holding a queue.
	 *
	 * WaitSelect over the listening socket fixes it: the same call carries
	 * an Exec signal mask and an optional timeout, so CTRL-C works and
	 * -t bounds the wait. An instrument -- or a daemon -- that cannot be
	 * stopped is not finished.
	 */
	{
		fd_set rd;
		struct timeval tv;
		LONG sigs = SIGBREAKF_CTRL_C;
		LONG n;

		FD_ZERO(&rd);
		FD_SET(listener, &rd);
		tv.tv_sec = wait_secs;
		tv.tv_usec = 0;

		n = WaitSelect(listener + 1, &rd, NULL, NULL,
		               wait_secs > 0 ? &tv : NULL, (ULONG *)&sigs);

		if (sigs & SIGBREAKF_CTRL_C)
		{
			say("telnetd: interrupted before any connection\n");
		}
		else if (n > 0 && FD_ISSET(listener, &rd))
		{
			conn = accept(listener, NULL, NULL);
			if (conn >= 0)
				run_session(conn);
			else
				say("telnetd: accept() failed\n");
		}
		else
		{
			say("telnetd: no connection within the timeout; exiting\n");
		}
	}

	CloseSocket(listener);
	CloseLibrary(SocketBase);
	if (logfh) { say("telnetd: exit\n"); Close(logfh); logfh = 0; }
	return RETURN_OK;
}
