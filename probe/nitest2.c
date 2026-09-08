/*
 * nitest2 -- find the NI_GETBYNAME calling convention, against a KNOWN answer.
 *
 * nitest asked unit 2 for "localhost" and got NIERR_NOTFOUND, even though
 * ENV:sys/net/hosts contains exactly that. So the request is wrong, not the
 * data. Rather than guess once more and carry the guess into the passwd
 * question, this tries several conventions against the unit whose answer is
 * already known. Whichever one returns localhost is the convention; the same
 * call then means something when aimed at unit 0.
 *
 * The header gives io_Data, io_Length and a ULONG io_Offset commented only
 * "search criteria", and there is no autodoc for netinfo.device anywhere on the
 * machine -- header, guide and HTML are the same text. So this is the cheapest
 * way to settle it.
 */

#include <exec/types.h>
#include <exec/io.h>
#include <exec/memory.h>
#include <dos/dos.h>
#include <devices/netinfo.h>
#include <proto/exec.h>
#include <proto/dos.h>

#include <string.h>

static void say(CONST_STRPTR s)
{
	BPTR o = Output();
	if (o) Write(o, (APTR)s, (LONG)strlen((const char *)s));
}

static void say_num(CONST_STRPTR p, LONG v)
{
	char b[32]; char *q = b + sizeof(b); ULONG u; BOOL neg = FALSE;
	if (v < 0) { neg = TRUE; u = (ULONG)(-v); } else u = (ULONG)v;
	*--q = '\n';
	if (!u) *--q = '0';
	else while (u && q > b) { *--q = (char)('0' + (u % 10)); u /= 10; }
	if (neg && q > b) *--q = '-';
	say(p); Write(Output(), q, (LONG)(b + sizeof(b) - q));
}

static struct MsgPort     *mp;
static struct NetInfoReq  *req;
static UBYTE               buf[4096];

/* Report an attempt, and if it succeeded, show what came back. */
static int attempt(CONST_STRPTR what)
{
	say("  "); say(what); say(" -> ");
	DoIO((struct IORequest *)req);

	if (req->io_Error == 0)
	{
		struct NetInfoHost *h = (struct NetInfoHost *)buf;
		say("SUCCESS\n");
		say_num("      io_Actual = ", (LONG)req->io_Actual);
		/* Only touch the result if it looks like it was filled in. */
		if (req->io_Actual > 0 && h->ho_domain != NULL)
		{
			say("      ho_domain = ");
			say((CONST_STRPTR)h->ho_domain);
			say("\n");
		}
		return 1;
	}
	say_num("error ", (LONG)req->io_Error);
	return 0;
}

int main(void)
{
	static const char *name = "localhost";
	int won = 0;

	mp = CreateMsgPort();
	req = mp ? (struct NetInfoReq *)CreateIORequest(mp, sizeof(struct NetInfoReq)) : NULL;
	if (!req) { say("nitest2: no ioreq\n"); return RETURN_FAIL; }

	if (OpenDevice((CONST_STRPTR)NETINFONAME, NETINFO_HOST_UNIT,
	               (struct IORequest *)req, 0) != 0)
	{
		say("nitest2: cannot open unit 2\n");
		return RETURN_FAIL;
	}
	say("nitest2: unit 2 (hosts) open; ENV:sys/net/hosts contains localhost\n");
	say("nitest2: trying conventions until one returns it\n\n");

	/* A: key in io_Offset, result in io_Data -- what nitest did. */
	memset(buf, 0, sizeof(buf));
	req->io_Command = NI_GETBYNAME;
	req->io_Data    = buf;
	req->io_Length  = sizeof(buf);
	req->io_Offset  = (ULONG)name;
	won |= attempt((CONST_STRPTR)"A: key in io_Offset, 4K result buffer");

	/* B: key copied INTO the result buffer, io_Offset zero. */
	memset(buf, 0, sizeof(buf));
	strcpy((char *)buf, name);
	req->io_Command = NI_GETBYNAME;
	req->io_Data    = buf;
	req->io_Length  = sizeof(buf);
	req->io_Offset  = 0;
	won |= attempt((CONST_STRPTR)"B: key in io_Data, io_Offset = 0");

	/* C: key in io_Data AND io_Offset -- some devices want both. */
	memset(buf, 0, sizeof(buf));
	strcpy((char *)buf, name);
	req->io_Command = NI_GETBYNAME;
	req->io_Data    = buf;
	req->io_Length  = sizeof(buf);
	req->io_Offset  = (ULONG)buf;
	won |= attempt((CONST_STRPTR)"C: key in io_Data, io_Offset points at it");

	/* D: maybe io_Length is the KEY length, not the buffer size. */
	memset(buf, 0, sizeof(buf));
	req->io_Command = NI_GETBYNAME;
	req->io_Data    = buf;
	req->io_Length  = (ULONG)strlen(name);
	req->io_Offset  = (ULONG)name;
	won |= attempt((CONST_STRPTR)"D: io_Length = key length");

	/* E: the whole request pre-zeroed except the essentials. */
	memset(buf, 0, sizeof(buf));
	req->io_Command = NI_GETBYNAME;
	req->io_Flags   = 0;
	req->io_Actual  = 0;
	req->io_Data    = buf;
	req->io_Length  = sizeof(buf);
	req->io_Offset  = (ULONG)name;
	won |= attempt((CONST_STRPTR)"E: as A, with io_Flags/io_Actual cleared");

	say(won ? "\nnitest2: a convention WORKED -- use it for unit 0\n"
	        : "\nnitest2: none worked; the fault is elsewhere\n");

	CloseDevice((struct IORequest *)req);
	DeleteIORequest((struct IORequest *)req);
	DeleteMsgPort(mp);
	return RETURN_OK;
}
