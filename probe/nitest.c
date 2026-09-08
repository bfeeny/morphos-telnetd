/*
 * nitest -- does netinfo.device work at all, and does unit 0 have anything?
 *
 * Four passwd-file edits have all produced "0 entries" from usergroup.library.
 * But a parser that rejects every line and a parser that never finds its
 * backing store look identical from there. This talks to the DEVICE directly
 * and skips usergroup entirely, so the answers separate:
 *
 *   OpenDevice fails                  -> the chain is broken at the device
 *   opens, host unit (2) works        -> the device is fine; passwd is the odd one
 *   opens, passwd unit (0) NOTFOUND   -> the store is reachable and empty
 *
 * Unit 2 (hosts) is the control. ENV:sys/net/hosts ships and contains
 * localhost, so if netinfo reads files at all, that lookup must succeed. If
 * hosts works and passwd does not, the device is healthy and the passwd store
 * specifically is not being read -- which is the question nobody has answered.
 *
 * Never prints a password field.
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

/* Try one unit: open it, look a name up, report precisely what happened. */
static void probe_unit(CONST_STRPTR label, LONG unit, const char *name)
{
	struct MsgPort  *mp;
	struct NetInfoReq *req;
	LONG err;

	say("\n=== "); say(label); say(" ===\n");

	mp = CreateMsgPort();
	if (!mp) { say("  no msgport\n"); return; }

	req = (struct NetInfoReq *)CreateIORequest(mp, sizeof(struct NetInfoReq));
	if (!req) { say("  no ioreq\n"); DeleteMsgPort(mp); return; }

	err = OpenDevice((CONST_STRPTR)NETINFONAME, unit, (struct IORequest *)req, 0);
	if (err != 0)
	{
		say_num("  OpenDevice FAILED, error = ", err);
		DeleteIORequest((struct IORequest *)req);
		DeleteMsgPort(mp);
		return;
	}
	say("  OpenDevice OK -- the device exists and this unit opened\n");

	{
		UBYTE buf[512];
		memset(buf, 0, sizeof(buf));

		req->io_Command = NI_GETBYNAME;
		req->io_Data    = buf;
		req->io_Length  = sizeof(buf);
		req->io_Offset  = (ULONG)name;

		DoIO((struct IORequest *)req);

		say("  NI_GETBYNAME(\""); say((CONST_STRPTR)name); say("\") -> ");
		if (req->io_Error == 0)
		{
			say("FOUND\n");
			say_num("    io_Actual = ", (LONG)req->io_Actual);
		}
		else
		{
			say("error\n");
			say_num("    io_Error = ", (LONG)req->io_Error);
			if (req->io_Error == NIERR_NOTFOUND)
				say("    (NIERR_NOTFOUND: the unit works, the name is not in it)\n");
		}
	}

	CloseDevice((struct IORequest *)req);
	DeleteIORequest((struct IORequest *)req);
	DeleteMsgPort(mp);
}

int main(int argc, char **argv)
{
	const char *user = (argc > 1 && argv[1][0]) ? argv[1] : "telnettest";

	say("nitest: talking to netinfo.device directly, bypassing usergroup\n");

	/* Control first: hosts ships with localhost in it. */
	probe_unit((CONST_STRPTR)"unit 2 HOST  (control: ENV:sys/net/hosts ships)",
	           NETINFO_HOST_UNIT, "localhost");

	probe_unit((CONST_STRPTR)"unit 4 SERVICE (control: services ships)",
	           NETINFO_SERVICE_UNIT, "telnet");

	probe_unit((CONST_STRPTR)"unit 0 PASSWD (the question)",
	           NETINFO_PASSWD_UNIT, user);

	say("\nnitest: done\n");
	return RETURN_OK;
}
