/*
 * conprobe -- does a fake console handler actually work on MorphOS?
 *
 * A PROBE, not a daemon. It answers the one question that decides this
 * project's architecture:
 *
 *   Can we spawn a native MorphOS Shell whose console is a MsgPort we own,
 *   and drive it entirely by answering AmigaDOS packets?
 *
 * There are no sockets here on purpose. Input is a canned script compiled in;
 * output goes to our own stdout. That isolates the single thing that cannot be
 * tested from the build host.
 *
 * All the decision logic lives in src/console_handler.c, which has no MorphOS
 * dependencies and is exercised by tests/run.sh on the host. This file is only
 * the glue: create the port, fabricate the handles, spawn the Shell, and pump
 * packets through the tested dispatcher.
 *
 * Provenance: MorphOS SDK 3.20 (sdk-20260529), os-include/dos/{dos,dosextens,
 * dostags}.h and Autodoc/dos.doc, inspected 2026-09-06. Prior art that pointed
 * at this API: telnetd 2.0 (1995, GPL) -- see doc/PRIOR-ART.md. No code copied.
 *
 * NO MEMORY PROTECTION. See the teardown note at the bottom: this program
 * deliberately leaks its message port rather than risk freeing one the Shell
 * may still hold a handle to.
 */

#include <exec/types.h>
#include <exec/ports.h>
#include <exec/memory.h>
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

/* What the console_handler callbacks operate on. */
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
/* The two callbacks. In telnetd these become socket reads and writes. */

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
	struct MsgPort      *port;
	struct FileHandle   *fh_in  = NULL;
	struct FileHandle   *fh_out = NULL;
	struct TagItem       systags[7];
	LONG                 rc;
	int                  status = RETURN_FAIL;

	/*
	 * Disable DOS requesters before anything else. This is normally run
	 * over a remote queue with nobody watching the screen, and a requester
	 * ("Please insert volume X:") waits for an answer that never comes --
	 * an unbreakable hang that also strands its locks until reboot.
	 * (MorphOS Programming Traps; learned the hard way by AmigaCode.)
	 */
	me = (struct Process *)FindTask(NULL);
	if (me != NULL)
		me->pr_WindowPtr = (APTR)-1;

	memset(&io, 0, sizeof(io));
	io.out = Output();

	say("conprobe: MorphOS fake-console-handler probe\n");
	say("conprobe: proving a Shell can be driven entirely by DOS packets\n\n");

	port = CreateMsgPort();
	if (port == NULL)
	{
		say("conprobe: FAILED -- CreateMsgPort()\n");
		return RETURN_FAIL;
	}

	fh_in = make_handle(port, MODE_OLDFILE, HANDLE_IN);
	fh_out = make_handle(port, MODE_NEWFILE, HANDLE_OUT);
	if (fh_in == NULL || fh_out == NULL)
	{
		say("conprobe: FAILED -- AllocDosObject()\n");
		if (fh_in)  FreeDosObject(DOS_FILEHANDLE, fh_in);
		if (fh_out) FreeDosObject(DOS_FILEHANDLE, fh_out);
		DeleteMsgPort(port);	/* safe: no Shell was ever started */
		return RETURN_FAIL;
	}

	/*
	 * SYS_FilterTags defaults to TRUE and strips NP_* tags before they
	 * reach CreateNewProc() -- NP_ConsoleTask would be silently dropped and
	 * this probe would prove nothing. (dos/dostags.h l.24.)
	 *
	 * SYS_Input and SYS_Output must be different filehandles; the autodoc
	 * forbids reusing one for both.
	 */
	systags[0].ti_Tag = SYS_Input;      systags[0].ti_Data = (IPTR)MKBADDR(fh_in);
	systags[1].ti_Tag = SYS_Output;     systags[1].ti_Data = (IPTR)MKBADDR(fh_out);
	systags[2].ti_Tag = SYS_Asynch;     systags[2].ti_Data = (IPTR)TRUE;
	systags[3].ti_Tag = SYS_FilterTags; systags[3].ti_Data = (IPTR)FALSE;
	systags[4].ti_Tag = NP_ConsoleTask; systags[4].ti_Data = (IPTR)port;
	systags[5].ti_Tag = NP_WindowPtr;   systags[5].ti_Data = (IPTR)-1;
	systags[6].ti_Tag = TAG_DONE;       systags[6].ti_Data = 0;

	/* SYS_Asynch also transfers ownership of both handles: the system
	 * closes them when the command finishes, and those closes are the
	 * ACTION_ENDs we count below. (dos.library/SystemTagList, NOTES.) */
	console_init(&st, probe_read, probe_write, &io, 2, MAX_PACKETS);

	say("conprobe: spawning Shell with NP_ConsoleTask = our port...\n");

	rc = SystemTagList("", systags);
	if (rc == -1)
	{
		say("conprobe: FAILED -- SystemTagList() could not start the Shell\n");
		say_num("conprobe: IoErr() = ", (LONG)IoErr());
		FreeDosObject(DOS_FILEHANDLE, fh_in);
		FreeDosObject(DOS_FILEHANDLE, fh_out);
		DeleteMsgPort(port);	/* safe: the Shell never started */
		return RETURN_FAIL;
	}

	say("conprobe: Shell started. Servicing packets.\n");
	say("conprobe: ---- shell output follows ----\n\n");

	for (;;)
	{
		struct Message   *msg;
		struct DosPacket *pkt;
		ULONG             sigs;

		sigs = Wait((1UL << port->mp_SigBit) | SIGBREAKF_CTRL_C);

		if ((sigs & SIGBREAKF_CTRL_C) && !st.draining)
		{
			say("\nconprobe: CTRL-C -- feeding EOF, waiting for the Shell to exit\n");
			console_begin_drain(&st);
		}

		while ((msg = GetMsg(port)) != NULL)
		{
			struct ConsoleReply reply;
			void *bufarg = NULL;
			LONG  len    = 0;

			pkt = (struct DosPacket *)msg->mn_Node.ln_Name;
			if (pkt == NULL)
				continue;	/* not a DOS packet; ignore */

			if (pkt->dp_Type == ACTION_READ || pkt->dp_Type == ACTION_WRITE)
			{
				bufarg = (void *)pkt->dp_Arg2;
				len    = pkt->dp_Arg3;
			}

			reply = console_dispatch(&st, pkt->dp_Type, pkt->dp_Arg1,
			                         bufarg, len);

			ReplyPkt(pkt, reply.res1, reply.res2);
		}

		if (console_session_finished(&st))
			break;
	}

	say("\n\nconprobe: ---- shell output ends ----\n");
	say_num("conprobe: packets serviced   = ", st.packets);
	say_num("conprobe: unknown packets    = ", st.unknown);
	say_num("conprobe: opens / closes     = ", st.opens_seen);
	say_num("conprobe:                      ", st.ends_seen);
	say_num("conprobe: last raw mode      = ", (LONG)st.raw_mode);
	say_num("conprobe: accounting broken? = ", (LONG)st.inconsistent);

	if (st.packets > 0 && io.script_pos > 0)
	{
		say("conprobe: RESULT -- the Shell read our packets. Mechanism CONFIRMED.\n");
		status = RETURN_OK;
	}
	else
	{
		say("conprobe: RESULT -- no input consumed. Mechanism NOT confirmed.\n");
		status = RETURN_WARN;
	}

	/*
	 * Teardown, and the most important decision in this file.
	 *
	 * We do NOT DeleteMsgPort(). Freeing a port that a Shell still holds a
	 * handle to means its next packet is written into freed memory, and on
	 * a machine with no memory protection that takes down the whole OS --
	 * including whatever the other agents sharing this machine were doing.
	 *
	 * The only thing that would stand between a bug in our packet
	 * accounting and that outcome is the packet accounting itself. That is
	 * the thing under test, so it does not get to authorise the dangerous
	 * operation: console_safe_to_free_port() always answers no.
	 *
	 * The cost is a leaked MsgPort -- a few hundred bytes until the next
	 * reboot. Nothing is reclaimed at exit on this platform either way.
	 * That is the right side of the trade by a wide margin.
	 *
	 * Likewise fh_in/fh_out: SYS_Asynch handed them to the system, which
	 * closed them. Freeing them here would be a double free.
	 */
	if (console_safe_to_free_port(&st))
		DeleteMsgPort(port);	/* unreachable today, by design */
	else
		say("conprobe: message port deliberately leaked (safe teardown).\n");

	return status;
}
