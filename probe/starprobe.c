/*
 * starprobe -- why does Open("*") fail on our console?
 *
 * RUN IT INSIDE A TELNET SESSION. Its console is then ours, which is the whole
 * point: it reports what a program sees when its console is a handler we wrote.
 *
 * THE QUESTION. ixemul maps "/dev/tty" to the AmigaDOS "*" (open.c:274), so
 * Open("*") failing is why pdksh reports "No controlling tty" and runs without
 * job control over telnet. The same "*" was rejected as a window description
 * when NewShell was first tried against this handler, which suggests one root
 * cause under both -- but that is a guess, and this exists to replace it.
 *
 * WHAT IT DISTINGUISHES. Two possibilities need opposite fixes:
 *
 *   dos.library sent us a packet and we answered it wrong  -> our bug
 *   dos.library never asked us at all                      -> not our bug
 *
 * This probe cannot see packets. What it CAN do is report the error code and
 * the process fields dos.library would have consulted, which narrows it a long
 * way before anyone turns on system-wide packet logging -- and if IoErr() names
 * something we returned, it settles it outright.
 *
 * It opens things and closes them. It changes nothing.
 */

#include <exec/types.h>
#include <dos/dos.h>
#include <dos/dosextens.h>
#include <proto/exec.h>
#include <proto/dos.h>

#include <string.h>

static void say(CONST_STRPTR s)
{
	BPTR out = Output();
	if (out)
		Write(out, (APTR)s, (LONG)strlen((const char *)s));
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
		BPTR out = Output();
		if (out)
			Write(out, p, (LONG)(buf + sizeof(buf) - p));
	}
}

/* Try one name, report what happened, and give the handle straight back. */
static void try_open(CONST_STRPTR name, LONG mode, CONST_STRPTR label)
{
	BPTR fh;

	say("\n--- Open(\"");
	say(name);
	say("\") ");
	say(label);
	say("\n");

	SetIoErr(0);
	fh = Open(name, mode);

	if (fh)
	{
		struct FileHandle *f = (struct FileHandle *)BADDR(fh);

		say("    RESULT: opened\n");
		say_num("    fh_Type (the handler port) = ", (LONG)(f ? f->fh_Type : NULL));
		say_num("    fh_Interactive             = ", (LONG)(f ? f->fh_Interactive : 0));
		say_num("    IsInteractive()            = ", (LONG)IsInteractive(fh));
		Close(fh);
		say("    (closed again)\n");
	}
	else
	{
		LONG e = IoErr();

		say("    RESULT: FAILED\n");
		say_num("    IoErr() = ", e);

		/*
		 * The codes worth recognising. 205 is what a handler returns
		 * when it knows the action and has no such object -- which is
		 * what THIS daemon answers for PARENT_FH and COPY_DIR_FH -- and
		 * 209 is "I do not know that action", which is what it answers
		 * for anything unrecognised. Seeing either would mean the packet
		 * reached us. Anything else points away from this handler.
		 */
		if (e == ERROR_OBJECT_NOT_FOUND)
			say("    = ERROR_OBJECT_NOT_FOUND (205)\n");
		else if (e == ERROR_ACTION_NOT_KNOWN)
			say("    = ERROR_ACTION_NOT_KNOWN (209) -- a handler refused it\n");
		else if (e == ERROR_OBJECT_WRONG_TYPE)
			say("    = ERROR_OBJECT_WRONG_TYPE (212)\n");
		else if (e == ERROR_INVALID_LOCK)
			say("    = ERROR_INVALID_LOCK (211)\n");
	}
}

int main(void)
{
	struct Process *me = (struct Process *)FindTask(NULL);

	say("starprobe -- why Open(\"*\") fails on a telnetd console\n");
	say("=====================================================\n");

	/*
	 * The fields dos.library consults to resolve "*".
	 *
	 * pr_ConsoleTask is what NP_ConsoleTask set when the Shell was spawned,
	 * and it is what "*" is supposed to resolve to. If it is NULL here, the
	 * answer is that nothing was ever asked of us -- dos.library had nowhere
	 * to send the packet -- and no amount of handler work would fix it.
	 */
	say("\n--- this process ---\n");
	say_num("    pr_ConsoleTask = ", (LONG)(me ? me->pr_ConsoleTask : NULL));
	say_num("    pr_CIS         = ", (LONG)(me ? me->pr_CIS : 0));
	say_num("    pr_COS         = ", (LONG)(me ? me->pr_COS : 0));
	say_num("    pr_CES         = ", (LONG)(me ? me->pr_CES : 0));

	if (me && me->pr_CIS)
	{
		struct FileHandle *f = (struct FileHandle *)BADDR(me->pr_CIS);
		say_num("    pr_CIS fh_Type      = ", (LONG)(f ? f->fh_Type : NULL));
		say_num("    pr_CIS fh_Interactive = ", (LONG)(f ? f->fh_Interactive : 0));
	}

	say_num("\n    Input()  IsInteractive = ", (LONG)IsInteractive(Input()));
	say_num("    Output() IsInteractive = ", (LONG)IsInteractive(Output()));

	/* The one that matters. */
	try_open((CONST_STRPTR)"*", MODE_OLDFILE, (CONST_STRPTR)"-- what /dev/tty becomes");

	/* For contrast: the named console device, and the system one. */
	try_open((CONST_STRPTR)"CONSOLE:", MODE_OLDFILE, (CONST_STRPTR)"-- the generic console");
	try_open((CONST_STRPTR)"NIL:", MODE_OLDFILE, (CONST_STRPTR)"-- a control: should always work");

	say("\ndone. Nothing was changed.\n");
	return RETURN_OK;
}
