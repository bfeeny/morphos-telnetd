/*
 * conprobe -- does a fake console handler actually work on MorphOS?
 *
 * A PROBE, not a daemon. It answers the one question that decides this
 * project's architecture:
 *
 *   Can we spawn a native MorphOS Shell whose console is a MsgPort we own,
 *   and drive it entirely by answering AmigaDOS packets?
 *
 * No sockets: input is a canned script compiled in, output goes to our own
 * stdout. That isolates the single thing that cannot be tested from the build
 * host. All the decision logic lives in src/console_handler.c, which has no
 * MorphOS dependencies and is exercised by tests/run.sh.
 *
 * ---------------------------------------------------------------------------
 * WHY THERE IS A HELPER PROCESS  (revision 2, after the first hardware run)
 *
 * Revision 1 called SystemTagList() from this process and hung: the output
 * stopped dead after "spawning Shell...", and SystemTagList() never returned.
 *
 * The reason is structural. Starting a Shell on our console requires somebody
 * to answer the DOS packets that Shell sends. If the process that owns the
 * handler port is sitting inside SystemTagList(), nobody can answer, and
 * SystemTagList() cannot return until someone does. Self-deadlock.
 *
 * So the handler process must never make the call. A helper process does it
 * and blocks there for the whole session; this process is in its packet loop
 * before the helper even starts. telnetd 2.0 (1995) has the same split, with
 * the comment "NO more DOS calls allowed after this one" immediately above it.
 *
 * The helper is created and awaited using the MorphOS idiom from the SDK's own
 * Examples/Misc/procmessages.c: NP_CodeType/CODETYPE_PPC + NP_Entry, with an
 * NP_StartupMsg that is automatically ReplyMsg'd when the helper exits. That
 * reply is how we learn the session is over without polling for it.
 * ---------------------------------------------------------------------------
 *
 * Provenance: MorphOS SDK 3.20 (sdk-20260529) os-include and Autodoc;
 * Examples/Misc/procmessages.c for the process idiom; the published AROS-
 * derived dos.library source for SystemTagList's documented tag-conflict list.
 * Prior art that pointed at the API: telnetd 2.0 (GPL) -- doc/PRIOR-ART.md.
 * No code copied.
 *
 * NO MEMORY PROTECTION. This program deliberately leaks its message port
 * rather than risk freeing one the Shell may still hold a handle to.
 */

#include <exec/types.h>
#include <exec/ports.h>
#include <exec/memory.h>
#include <exec/tasks.h>
#include <exec/io.h>
#include <devices/timer.h>
#include <dos/dos.h>
#include <dos/dosextens.h>
#include <dos/dostags.h>
#include <proto/exec.h>
#include <proto/dos.h>

#include <string.h>

#include "../src/console_handler.h"

/* The canned session: stands in for "bytes arriving from a socket". */
static const char script[] =
	"version\n"
	"echo \"conprobe: the shell is alive and reading our packets\"\n"
	"cd RAM:\n"
	"echo \"conprobe: cd worked, cwd is now RAM:\"\n"
	"endcli\n";

#define HANDLE_IN   1
#define HANDLE_OUT  2
#define MAX_PACKETS 20000

/* Passed to the helper process, and ReplyMsg'd back to us when it exits. */
struct SpawnMsg
{
	struct Message msg;	/* MUST be first */

	CONST_STRPTR command;	/* NULL = RUN_EXECUTE (shell reads our input) */
	BPTR  input;		/* handles the helper hands to the Shell */
	BPTR  output;
	APTR  console_port;	/* our handler port, for NP_ConsoleTask */

	LONG  rc;		/* what SystemTagList() returned */
	LONG  ioerr;		/* IoErr() if it failed */
	LONG  started;		/* did the call happen at all? */
};

struct ProbeIO
{
	ULONG script_pos;
	ULONG bytes_out;	/* how much the Shell actually wrote to us */
	int   line_mode;	/* answer reads a line at a time, as cooked consoles do */
	BPTR  out;
};

/*
 * Every packet type we are sent, in order. Recorded rather than printed
 * inline so the trace cannot interleave with the Shell's own output -- and
 * dumped at the end even on the paths where nothing else happens.
 *
 * Rev 2 shipped without this and immediately needed it: the Shell sent two
 * packet types we do not implement, and the run could not say which.
 */
#define TRACE_MAX 128
static LONG trace[TRACE_MAX];
static LONG trace_req[TRACE_MAX];	/* dp_Arg3: bytes asked for */
static LONG trace_got[TRACE_MAX];	/* dp_Res1: what we answered */
static LONG trace_n = 0;

static void trace_add(LONG type, LONG req, LONG got)
{
	if (trace_n < TRACE_MAX)
	{
		trace[trace_n]     = type;
		trace_req[trace_n] = req;
		trace_got[trace_n] = got;
		trace_n++;
	}
}

/* ------------------------------------------------------------------ */

static void say(CONST_STRPTR s)
{
	BPTR out = Output();

	if (out)
		Write(out, (APTR)s, (LONG)strlen(s));
}

static void say_num(CONST_STRPTR prefix, LONG value)
{
	char  buf[32];
	char *p = buf + sizeof(buf);
	ULONG v;
	BOOL  neg = FALSE;

	if (value < 0) { neg = TRUE; v = (ULONG)(-value); }
	else           { v = (ULONG)value; }

	*--p = '\n';
	if (v == 0)
	{
		*--p = '0';
	}
	else
	{
		while (v > 0 && p > buf)
		{
			*--p = (char)('0' + (v % 10));
			v /= 10;
		}
	}
	if (neg && p > buf)
		*--p = '-';

	say(prefix);
	Write(Output(), p, (LONG)(buf + sizeof(buf) - p));
}

/* ------------------------------------------------------------------ */
/* Callbacks. In telnetd these become socket reads and writes.         */

static long probe_read(void *ctx, void *buf, long len)
{
	struct ProbeIO *io = (struct ProbeIO *)ctx;
	ULONG avail = (ULONG)(sizeof(script) - 1) - io->script_pos;
	long  n;

	if (avail == 0)
		return 0;	/* end of canned input == the remote hung up */

	n = ((ULONG)len < avail) ? len : (long)avail;

	/*
	 * A cooked console hands over one line at a time. Answering with the
	 * whole buffer is what a *file* does -- and a Shell reading a script may
	 * treat "asked 200, got 127" as end-of-file, which is exactly the
	 * behaviour we are chasing. Opt in with -l so the two cases stay
	 * distinguishable on the wire.
	 */
	if (io->line_mode)
	{
		long i;
		for (i = 0; i < n; i++)
			if (script[io->script_pos + i] == '\n') { n = i + 1; break; }
	}

	CopyMem((APTR)(script + io->script_pos), buf, n);
	io->script_pos += (ULONG)n;

	return n;
}

static long probe_write(void *ctx, const void *buf, long len)
{
	struct ProbeIO *io = (struct ProbeIO *)ctx;

	if (io->out)
		Write(io->out, (APTR)buf, len);

	io->bytes_out += (ULONG)len;
	return len;
}

/* ------------------------------------------------------------------ */
/* The helper process.                                                 */

/*
 * Runs as its own process so that blocking here does not stop the handler.
 * It blocks inside SystemTagList() for the entire life of the Shell, then
 * closes the two handles -- and those closes are the ACTION_END packets the
 * handler counts to learn the session is over.
 *
 * Deliberately NOT using SYS_Asynch. Without it the caller owns the handles
 * and must close them (dos.library/SystemTagList, NOTES), which is exactly
 * the signal we want. With it, the system closes them at a moment we do not
 * control.
 */
static void spawn_helper(void)
{
	struct SpawnMsg *sm = NULL;
	struct TagItem   attrtags[1];
	struct TagItem   systags[7];

	attrtags[0].ti_Tag = TAG_DONE;
	attrtags[0].ti_Data = 0;

	if (!NewGetTaskAttrsA(NULL, &sm, sizeof(struct SpawnMsg *),
	                      TASKINFOTYPE_STARTUPMSG, attrtags) || sm == NULL)
		return;	/* nothing we can do; the reply still fires at exit */

	/*
	 * NP_ConsoleTask is what makes the spawned Shell treat our port as its
	 * console. SYS_FilterTags must be FALSE or NP_* tags are stripped
	 * before reaching CreateNewProc() and this would silently do nothing
	 * (dos/dostags.h l.24).
	 *
	 * NP_Cli is deliberately absent: SystemTagList() documents it among the
	 * tags it manages itself and does not pass through, so setting it here
	 * would be ignored. (telnetd 2.0 passes it; per the documented conflict
	 * list it can never have had an effect.)
	 */
	systags[0].ti_Tag = SYS_Input;      systags[0].ti_Data = (IPTR)sm->input;
	systags[1].ti_Tag = SYS_Output;     systags[1].ti_Data = (IPTR)sm->output;
	systags[2].ti_Tag = SYS_FilterTags; systags[2].ti_Data = (IPTR)FALSE;
	systags[3].ti_Tag = NP_ConsoleTask; systags[3].ti_Data = (IPTR)sm->console_port;
	systags[4].ti_Tag = NP_WindowPtr;   systags[4].ti_Data = (IPTR)-1;
	/*
	 * NP_Cli, restored -- with a caveat worth recording.
	 *
	 * SystemTagList() documents NP_Cli among the tags it manages itself and
	 * does not pass through, which is why rev 2 dropped it. But we also set
	 * SYS_FilterTags = FALSE, and that switch exists precisely to stop
	 * SystemTagList() filtering what reaches CreateNewProc(). If filtering
	 * off also means "manage nothing", then the tag becomes ours to supply
	 * and its absence would explain a Shell that reads once and exits
	 * without ever running a command.
	 *
	 * Untested hypothesis, deliberately isolated: this is the only change
	 * from the run that produced READ + END + END.
	 */
	systags[5].ti_Tag = NP_Cli;         systags[5].ti_Data = (IPTR)TRUE;
	systags[6].ti_Tag = TAG_DONE;       systags[6].ti_Data = 0;

	/*
	 * NULL, not "".
	 *
	 * Rev 2 passed an empty string and the Shell exited immediately without
	 * ever reading: 6 packets, no ACTION_READ, rc=0. The published AROS
	 * dos.library source explains it --
	 *
	 *   type = (command == NULL) ? RUN_EXECUTE
	 *        : isAsynchronous ? RUN_SYSTEM_ASYNCH : RUN_SYSTEM;
	 *
	 * -- so "" is not "no command", it is RUN_SYSTEM with an empty command:
	 * run nothing, return 0. NULL selects RUN_EXECUTE, the Execute() path,
	 * which reads commands from SYS_Input until EOF. That is the interactive
	 * shell we actually want.
	 */
	sm->started = 1;
	sm->rc      = SystemTagList(sm->command, systags);
	sm->ioerr   = (LONG)IoErr();

	/*
	 * Close under Forbid() so both ACTION_ENDs are queued to the handler
	 * before we can be rescheduled -- the handler must not see the count
	 * reach zero, act on it, and then receive a second close.
	 */
	Forbid();
	if (sm->input)  Close(sm->input);
	if (sm->output) Close(sm->output);
	sm->input  = 0;
	sm->output = 0;
	Permit();

	/* Returning replies the startup message, which is how the parent
	 * learns we are done. */
}

/* ------------------------------------------------------------------ */

static struct FileHandle *make_handle(struct MsgPort *port, LONG mode, LONG id)
{
	struct FileHandle *fh;
	struct TagItem     tags[2];

	tags[0].ti_Tag  = ADO_FH_Mode;
	tags[0].ti_Data = (IPTR)mode;
	tags[1].ti_Tag  = TAG_DONE;
	tags[1].ti_Data = 0;

	fh = (struct FileHandle *)AllocDosObject(DOS_FILEHANDLE, tags);
	if (fh == NULL)
		return NULL;

	fh->fh_Type        = port;
	fh->fh_Interactive = DOSTRUE;	/* aka fh_Port: marks it a console */
	fh->fh_Arg1        = id;

	return fh;
}

/* ------------------------------------------------------------------ */

/*
 * A self-imposed deadline.
 *
 * The first interactive run proved the probe could wait forever: the Shell
 * stayed alive holding our handles, the packet loop had nothing to do, and
 * `bounded 60` could not help because a MorphOS process parked in Wait() does
 * not answer to a shell-level kill. It sat on the queue until the agent's own
 * 900s watchdog fired, and the process itself survived that.
 *
 * An instrument that can strand the machine it measures is not finished. So
 * the probe now carries its own clock: at the first deadline it starts
 * draining (feed EOF, let the Shell leave of its own accord), and at the
 * second it gives up, prints everything it learned, and exits -- leaking the
 * port, as it always does, because that is still the safe direction.
 */
struct Watchdog
{
	struct MsgPort   *port;
	struct timerequest *req;
	int               open;
	int               pending;
};

static int watchdog_start(struct Watchdog *w, ULONG secs)
{
	w->port = CreateMsgPort();
	if (w->port == NULL)
		return 0;

	w->req = (struct timerequest *)CreateIORequest(w->port, sizeof(struct timerequest));
	if (w->req == NULL)
		return 0;

	if (OpenDevice(TIMERNAME, UNIT_VBLANK, (struct IORequest *)w->req, 0) != 0)
		return 0;

	w->open = 1;
	w->req->tr_node.io_Command = TR_ADDREQUEST;
	w->req->tr_time.tv_secs    = secs;
	w->req->tr_time.tv_micro   = 0;
	SendIO((struct IORequest *)w->req);
	w->pending = 1;
	return 1;
}

static void watchdog_rearm(struct Watchdog *w, ULONG secs)
{
	if (!w->open)
		return;
	w->req->tr_node.io_Command = TR_ADDREQUEST;
	w->req->tr_time.tv_secs    = secs;
	w->req->tr_time.tv_micro   = 0;
	SendIO((struct IORequest *)w->req);
	w->pending = 1;
}

static void watchdog_stop(struct Watchdog *w)
{
	if (w->pending)
	{
		AbortIO((struct IORequest *)w->req);
		WaitIO((struct IORequest *)w->req);
		w->pending = 0;
	}
	if (w->open)   { CloseDevice((struct IORequest *)w->req); w->open = 0; }
	if (w->req)    { DeleteIORequest((struct IORequest *)w->req); w->req = NULL; }
	if (w->port)   { DeleteMsgPort(w->port); w->port = NULL; }
}

int main(int argc, char **argv)
{
	struct Watchdog      wd;
	struct DosList      *devnode = NULL;
	CONST_STRPTR         mount_name = NULL;
	int                  gave_up = 0;
	ULONG                deadline = 25;
	struct ConsoleState  st;
	struct ProbeIO       io;
	struct Process      *me;
	struct MsgPort      *port      = NULL;
	struct MsgPort      *replyport = NULL;
	struct SpawnMsg     *sm        = NULL;
	struct FileHandle   *fh_in     = NULL;
	struct FileHandle   *fh_out    = NULL;
	struct Process      *helper;
	struct TagItem       proctags[7];
	int                  helper_done = 0;
	int                  status = RETURN_FAIL;

	memset(&wd, 0, sizeof(wd));

	/*
	 * Disable DOS requesters first. This runs over a remote queue with
	 * nobody watching the screen, where a requester waits for an answer
	 * that never comes -- an unbreakable hang that also strands its locks
	 * until reboot. (MorphOS Programming Traps.)
	 */
	me = (struct Process *)FindTask(NULL);
	if (me != NULL)
		me->pr_WindowPtr = (APTR)-1;

	memset(&io, 0, sizeof(io));
	io.out = Output();

	say("conprobe: MorphOS fake-console-handler probe (rev 2, helper process)\n");
	say("conprobe: proving a Shell can be driven entirely by DOS packets\n\n");

	port      = CreateMsgPort();
	replyport = CreateMsgPort();
	sm        = AllocVec(sizeof(struct SpawnMsg), MEMF_PUBLIC | MEMF_CLEAR);

	if (port == NULL || replyport == NULL || sm == NULL)
	{
		say("conprobe: FAILED -- out of memory creating ports/message\n");
		goto cleanup_before_helper;
	}

	fh_in  = make_handle(port, MODE_OLDFILE, HANDLE_IN);
	fh_out = make_handle(port, MODE_NEWFILE, HANDLE_OUT);
	if (fh_in == NULL || fh_out == NULL)
	{
		say("conprobe: FAILED -- AllocDosObject()\n");
		goto cleanup_before_helper;
	}

	sm->msg.mn_Node.ln_Type = NT_MESSAGE;
	sm->msg.mn_ReplyPort    = replyport;
	sm->msg.mn_Length       = sizeof(struct SpawnMsg);
	sm->input               = MKBADDR(fh_in);
	sm->output              = MKBADDR(fh_out);
	sm->console_port        = (APTR)port;

	/*
	 * With no argument: NULL command == RUN_EXECUTE, i.e. "shell, read your
	 * commands from SYS_Input" -- the interactive case we ultimately want.
	 * With an argument: run exactly that command, which isolates the OUTPUT
	 * path (does ACTION_WRITE reach us?) from the INPUT path (will a shell
	 * actually consume a script from our handle?). Being able to switch
	 * without a rebuild is the difference between one round trip and three.
	 */
	/*
	 * Canned commands rather than free text. There are three shells between
	 * the build host and this program -- bash, the agent's pdksh, and
	 * AmigaDOS -- and "NewShell *" arrived here as 'NewShell "', which
	 * NewShell rejected with rc=10. Anything containing a quote or a star
	 * cannot survive that trip intact, so the interesting commands are
	 * spelled here where no shell can touch them.
	 */
	if (argc > 1 && argv[1] && argv[1][0] == '-' && argv[1][1] == 'M')
	{
		/* Same mount, but with CON:-style geometry appended. "invalid
		 * window description" suggests NewShell parses the string for
		 * x/y/w/h/title rather than treating it as a bare device name. */
		mount_name  = "TELCON";
		sm->command = (CONST_STRPTR)"NewShell TELCON:0/0/640/200/Telnet";
		say("conprobe: mode = mount TELCON: + NewShell with CON-style geometry\n");
	}
	else if (argc > 1 && argv[1] && argv[1][0] == '-' && argv[1][1] == 'm')
	{
		/*
		 * Mount ourselves as a named DOS device, then start a Shell on it.
		 *
		 * NewShell rejected both "*" and "CONSOLE:" as an invalid window
		 * description: it wants a name it can Open(). MorphOS's own
		 * consoles are handlers of exactly this kind -- MOSSYS:L has
		 * MUICON-Handler and FLOWCON-Handler -- and they are reachable
		 * because they are mounted under names. Ours had no name, which
		 * is the whole difference.
		 *
		 * MakeDosEntry(DLT_DEVICE) + dol_Task = our port + AddDosEntry()
		 * registers the name. No handler seglist is involved: we are the
		 * handler, already running.
		 *
		 * This is what ttyhandler did in 1996 with TTY:.
		 */
		mount_name = "TELCON";
		sm->command = (CONST_STRPTR)"NewShell TELCON:";
		say("conprobe: mode = mount as TELCON: then NewShell on it\n");
	}
	else if (argc > 1 && argv[1] && argv[1][0] == '-' && argv[1][1] == 'c')
	{
		/*
		 * CONSOLE: is the name that resolves through pr_ConsoleTask --
		 * i.e. to us. The SystemTagList autodoc says as much when it
		 * describes the shell "opening CONSOLE: on that handler".
		 * "NewShell *" is rejected here as an invalid window description.
		 */
		sm->command = (CONST_STRPTR)"NewShell CONSOLE:";
		say("conprobe: mode = NewShell CONSOLE: (resolves via pr_ConsoleTask)\n");
	}
	else if (argc > 1 && argv[1] && argv[1][0] == '-' && argv[1][1] == 'o')
	{
		/*
		 * The arrangement the autodoc actually recommends for a console:
		 * give SYS_Input only, leave SYS_Output NULL, and let the shell
		 * open CONSOLE: on our handler for its output.
		 */
		sm->command   = NULL;
		sm->output    = 0;
		say("conprobe: mode = interactive, SYS_Output NULL (shell opens CONSOLE:)\n");
	}
	else if (argc > 1 && argv[1] && argv[1][0] == '-' && argv[1][1] == 'n')
	{
		sm->command = (CONST_STRPTR)"NewShell *";
		say("conprobe: mode = NewShell on our console (as telnetd 2.0 does)\n");
	}
	else if (argc > 1 && argv[1] && argv[1][0] == '-' && argv[1][1] == 's')
	{
		sm->command = (CONST_STRPTR)"C:Shell";
		say("conprobe: mode = C:Shell on our console\n");
	}
	else if (argc > 1 && argv[1] && argv[1][0] == '-' && argv[1][1] == 'l')
	{
		io.line_mode = 1;
		sm->command  = NULL;
		say("conprobe: mode = interactive, reads answered ONE LINE at a time\n");
	}
	else if (argc > 1 && argv[1] && argv[1][0])
	{
		sm->command = (CONST_STRPTR)argv[1];
		say("conprobe: mode = run one command: ");
		say((CONST_STRPTR)sm->command); say("\n");
	}
	else
	{
		sm->command = NULL;
		say("conprobe: mode = interactive, reads answered in full\n");
	}

	console_init(&st, probe_read, probe_write, &io,
	             sm->output ? 2 : 1, MAX_PACKETS);

	proctags[0].ti_Tag = NP_CodeType;   proctags[0].ti_Data = CODETYPE_PPC;
	proctags[1].ti_Tag = NP_Entry;      proctags[1].ti_Data = (IPTR)spawn_helper;
	proctags[2].ti_Tag = NP_StartupMsg; proctags[2].ti_Data = (IPTR)sm;
	proctags[3].ti_Tag = NP_Name;       proctags[3].ti_Data = (IPTR)"conprobe helper";
	proctags[4].ti_Tag = NP_WindowPtr;  proctags[4].ti_Data = (IPTR)-1;
	/*
	 * Give the helper a CLI of its own.
	 *
	 * It is created with NP_Entry and so has no CLI structure. Running a
	 * single command through System() works without one -- `version` printed
	 * through our handler. But RUN_EXECUTE (a NULL command, "shell, read your
	 * commands from SYS_Input") consistently reads the whole script and
	 * produces nothing, which is what a shell that never actually starts
	 * would look like. NP_Cli here is on CreateNewProc, where it is ours to
	 * set -- unlike on SystemTagList, which documents it among the tags it
	 * manages itself.
	 */
	proctags[5].ti_Tag = NP_Cli;        proctags[5].ti_Data = (IPTR)TRUE;
	proctags[6].ti_Tag = TAG_DONE;      proctags[6].ti_Data = 0;

	if (mount_name)
	{
		devnode = MakeDosEntry((CONST_STRPTR)mount_name, DLT_DEVICE);
		if (devnode == NULL)
		{
			say("conprobe: FAILED -- MakeDosEntry()\n");
			goto cleanup_before_helper;
		}
		devnode->dol_Task = port;
		if (!AddDosEntry(devnode))
		{
			say("conprobe: FAILED -- AddDosEntry() (name already taken?)\n");
			FreeDosEntry(devnode);
			devnode = NULL;
			goto cleanup_before_helper;
		}
		say("conprobe: mounted our port as TELCON:\n");
	}

	say("conprobe: starting helper process to call SystemTagList()...\n");

	helper = CreateNewProc(proctags);
	if (helper == NULL)
	{
		say("conprobe: FAILED -- CreateNewProc() for the helper\n");
		goto cleanup_before_helper;
	}

	if (!watchdog_start(&wd, deadline))
		say("conprobe: WARNING -- no timer; running without a deadline\n");

	say("conprobe: helper running; this process is now the console handler.\n");
	say("conprobe: ---- shell output follows ----\n\n");

	/*
	 * From here on we are the handler. Everything below must be safe to run
	 * while a live Shell holds handles pointing into our memory.
	 */
	while (!helper_done || !console_session_finished(&st))
	{
		struct Message   *msg;
		struct DosPacket *pkt;
		ULONG             sigs;

		sigs = Wait((1UL << port->mp_SigBit)
		          | (1UL << replyport->mp_SigBit)
		          | (wd.port ? (1UL << wd.port->mp_SigBit) : 0)
		          | SIGBREAKF_CTRL_C);

		if ((sigs & SIGBREAKF_CTRL_C) && !st.draining)
		{
			say("\nconprobe: CTRL-C -- feeding EOF, waiting for the Shell to exit\n");
			console_begin_drain(&st);
		}

		if (wd.port && (sigs & (1UL << wd.port->mp_SigBit)))
		{
			while (GetMsg(wd.port) != NULL)
				wd.pending = 0;

			if (!st.draining)
			{
				say("\nconprobe: deadline -- draining (feeding EOF)\n");
				console_begin_drain(&st);
				watchdog_rearm(&wd, deadline);
			}
			else
			{
				say("\nconprobe: deadline again -- the Shell will not leave.\n");
				say("conprobe: giving up and reporting. The Shell stays resident.\n");
				gave_up = 1;
				break;
			}
		}

		/* Service the Shell first: the helper cannot finish until it does. */
		while ((msg = GetMsg(port)) != NULL)
		{
			struct ConsoleReply reply;
			void *bufarg = NULL;
			LONG  len    = 0;

			pkt = (struct DosPacket *)msg->mn_Node.ln_Name;
			if (pkt == NULL)
				continue;

			if (pkt->dp_Type == ACTION_READ || pkt->dp_Type == ACTION_WRITE)
			{
				bufarg = (void *)pkt->dp_Arg2;
				len    = pkt->dp_Arg3;
			}

			reply = console_dispatch(&st, pkt->dp_Type, pkt->dp_Arg1,
			                         bufarg, len);
			trace_add(pkt->dp_Type,
			          (pkt->dp_Type == ACTION_READ || pkt->dp_Type == ACTION_WRITE)
			              ? len : pkt->dp_Arg1,
			          reply.res1);
			ReplyPkt(pkt, reply.res1, reply.res2);
		}

		while (GetMsg(replyport) != NULL)
			helper_done = 1;	/* the helper process has exited */
	}

	watchdog_stop(&wd);

	say("\n\nconprobe: ---- shell output ends ----\n");
	say_num("conprobe: gave up on deadline?  = ", (LONG)gave_up);
	say_num("conprobe: SystemTagList rc     = ", sm->rc);
	if (sm->rc == -1)
		say_num("conprobe: IoErr()             = ", sm->ioerr);
	say_num("conprobe: helper reached call? = ", sm->started);
	say_num("conprobe: packets serviced     = ", st.packets);
	say_num("conprobe: unknown packets      = ", st.unknown);
	say_num("conprobe: opens                = ", st.opens_seen);
	say_num("conprobe: closes               = ", st.ends_seen);
	say_num("conprobe: last raw mode        = ", (LONG)st.raw_mode);
	say_num("conprobe: accounting broken?   = ", (LONG)st.inconsistent);
	say_num("conprobe: bytes in  (we fed)   = ", (LONG)io.script_pos);
	say_num("conprobe: bytes out (shell)    = ", (LONG)io.bytes_out);
	say_num("conprobe: CHANGE_SIGNALs       = ", st.signals_seen);
	say_num("conprobe: signal task (^C tgt) = ", (LONG)st.signal_task);

	{
		LONG i;
		say("conprobe: packet trace -- type / arg (len for R+W) / answered:\n");
		for (i = 0; i < trace_n; i++)
		{
			say_num("conprobe:   type ", trace[i]);
			say_num("conprobe:        asked ", trace_req[i]);
			say_num("conprobe:        gave  ", trace_got[i]);
		}
		if (trace_n == 0)
			say("conprobe:   (none)\n");
	}

	if (io.bytes_out > 0 && io.script_pos > 0)
	{
		say("conprobe: RESULT -- input consumed AND output produced. FULL SESSION.\n");
		status = RETURN_OK;
	}
	else if (io.bytes_out > 0)
	{
		say("conprobe: RESULT -- output path works (shell wrote through us).\n");
		status = RETURN_OK;
	}
	else if (io.script_pos > 0)
	{
		say("conprobe: RESULT -- input path works, but the shell produced nothing.\n");
		status = RETURN_WARN;
	}
	else if (sm->started && sm->rc == -1)
	{
		say("conprobe: RESULT -- the Shell could not be started; see IoErr above.\n");
		status = RETURN_WARN;
	}
	else
	{
		say("conprobe: RESULT -- no input consumed. Mechanism NOT confirmed.\n");
		status = RETURN_WARN;
	}

	/*
	 * Teardown, and the most important decision in this file.
	 *
	 * We do NOT DeleteMsgPort(port), and we do NOT free the two FileHandles.
	 * The helper closed the handles; freeing a port a Shell might still hold
	 * a handle to is the one mistake here that takes down the whole OS rather
	 * than failing politely -- along with whatever the other agents sharing
	 * this machine were doing.
	 *
	 * The only thing that could vouch for it being safe is our own packet
	 * accounting, which is the thing under test, so it does not get to
	 * authorise the dangerous operation: console_safe_to_free_port() always
	 * answers no. A leaked port costs a few hundred bytes until the next
	 * reboot, and nothing is reclaimed at process exit here anyway.
	 *
	 * replyport and sm are ours alone and the helper has exited (we waited
	 * for its reply), so those are genuinely safe to release.
	 */
	if (devnode)
	{
		if (!gave_up && console_session_finished(&st))
		{
			/* Removing the name cannot strand an open handle: those
			 * reference the port directly, not the entry. */
			if (RemDosEntry(devnode))
			{
				FreeDosEntry(devnode);
				say("conprobe: TELCON: unmounted.\n");
			}
		}
		else
		{
			say("conprobe: TELCON: left mounted (session did not end cleanly).\n");
		}
	}

	if (console_safe_to_free_port(&st))
		DeleteMsgPort(port);	/* unreachable today, by design */
	else
		say("conprobe: handler port deliberately leaked (safe teardown).\n");

	if (helper_done)
	{
		if (replyport) DeleteMsgPort(replyport);
		if (sm)        FreeVec(sm);
	}

	return status;

cleanup_before_helper:
	/*
	 * Only reachable before any Shell exists, so these are safe to release
	 * -- which is precisely why this path is separate from the one above.
	 * Revision 1 had a single teardown that freed handles and the port even
	 * when SystemTagList() had already been called, which would have freed
	 * objects a live Shell could still hold.
	 */
	if (fh_in)     FreeDosObject(DOS_FILEHANDLE, fh_in);
	if (fh_out)    FreeDosObject(DOS_FILEHANDLE, fh_out);
	if (sm)        FreeVec(sm);
	if (replyport) DeleteMsgPort(replyport);
	if (port)      DeleteMsgPort(port);

	return RETURN_FAIL;
}
