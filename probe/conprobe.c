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
	BPTR  out;
};

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
	CopyMem((APTR)(script + io->script_pos), buf, n);
	io->script_pos += (ULONG)n;

	return n;
}

static long probe_write(void *ctx, const void *buf, long len)
{
	struct ProbeIO *io = (struct ProbeIO *)ctx;

	if (io->out)
		Write(io->out, (APTR)buf, len);

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
	struct TagItem   systags[6];

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
	systags[5].ti_Tag = TAG_DONE;       systags[5].ti_Data = 0;

	sm->started = 1;
	sm->rc      = SystemTagList("", systags);
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

int main(void)
{
	struct ConsoleState  st;
	struct ProbeIO       io;
	struct Process      *me;
	struct MsgPort      *port      = NULL;
	struct MsgPort      *replyport = NULL;
	struct SpawnMsg     *sm        = NULL;
	struct FileHandle   *fh_in     = NULL;
	struct FileHandle   *fh_out    = NULL;
	struct Process      *helper;
	struct TagItem       proctags[6];
	int                  helper_done = 0;
	int                  status = RETURN_FAIL;

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

	console_init(&st, probe_read, probe_write, &io, 2, MAX_PACKETS);

	proctags[0].ti_Tag = NP_CodeType;   proctags[0].ti_Data = CODETYPE_PPC;
	proctags[1].ti_Tag = NP_Entry;      proctags[1].ti_Data = (IPTR)spawn_helper;
	proctags[2].ti_Tag = NP_StartupMsg; proctags[2].ti_Data = (IPTR)sm;
	proctags[3].ti_Tag = NP_Name;       proctags[3].ti_Data = (IPTR)"conprobe helper";
	proctags[4].ti_Tag = NP_WindowPtr;  proctags[4].ti_Data = (IPTR)-1;
	proctags[5].ti_Tag = TAG_DONE;      proctags[5].ti_Data = 0;

	say("conprobe: starting helper process to call SystemTagList()...\n");

	helper = CreateNewProc(proctags);
	if (helper == NULL)
	{
		say("conprobe: FAILED -- CreateNewProc() for the helper\n");
		goto cleanup_before_helper;
	}

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
		          | SIGBREAKF_CTRL_C);

		if ((sigs & SIGBREAKF_CTRL_C) && !st.draining)
		{
			say("\nconprobe: CTRL-C -- feeding EOF, waiting for the Shell to exit\n");
			console_begin_drain(&st);
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
			ReplyPkt(pkt, reply.res1, reply.res2);
		}

		while (GetMsg(replyport) != NULL)
			helper_done = 1;	/* the helper process has exited */
	}

	say("\n\nconprobe: ---- shell output ends ----\n");
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

	if (st.packets > 0 && io.script_pos > 0)
	{
		say("conprobe: RESULT -- the Shell read our packets. Mechanism CONFIRMED.\n");
		status = RETURN_OK;
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
