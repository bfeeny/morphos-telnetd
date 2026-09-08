/*
 * nitest3 -- can netinfo.device be WRITTEN, and does a written entry read back?
 *
 * Five different NI_GETBYNAME conventions all returned NIERR_NOTFOUND against a
 * unit whose backing file demonstrably contains the key. So the request shape
 * is not the problem, and the likeliest remaining explanation is that netinfo's
 * store is not "whatever is in ENV:sys/net/*" at all: those files are read by
 * bsdsocket's own resolver, while netinfo keeps a store that starts EMPTY and
 * has to be populated through CMD_UPDATE.
 *
 * The header supports that reading:
 *     #define NETINFOLENGTH_SAVEMODE -1
 *     "Only used with CMD_UPDATE and io_Length to decide the store policy"
 * -- a write path with a notion of persisting versus not.
 *
 * If a written entry reads back, the whole passwd question is answered: entries
 * are added through the device, not by editing a file behind its back, and
 * every hand-edited file tonight was ignored for that reason.
 *
 * Writes a DISTINCTIVE throwaway host name so it cannot collide with anything
 * real, and does NOT use save mode, so nothing should be persisted to disk.
 */

#include <exec/types.h>
#include <exec/io.h>
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

int main(void)
{
	struct MsgPort *mp;
	struct NetInfoReq *req;
	struct NetInfoHost h;
	static UBYTE name[] = "nitest-probe-host";
	static UBYTE addr[] = "10.99.99.99";
	UBYTE buf[2048];

	mp = CreateMsgPort();
	req = mp ? (struct NetInfoReq *)CreateIORequest(mp, sizeof(struct NetInfoReq)) : NULL;
	if (!req) { say("nitest3: no ioreq\n"); return RETURN_FAIL; }

	if (OpenDevice((CONST_STRPTR)NETINFONAME, NETINFO_HOST_UNIT,
	               (struct IORequest *)req, 0) != 0)
	{
		say("nitest3: cannot open unit 2\n");
		return RETURN_FAIL;
	}
	say("nitest3: unit 2 (hosts) open\n");

	/* 1. Confirm it is absent to begin with, so a later hit means something. */
	memset(buf, 0, sizeof(buf));
	req->io_Command = NI_GETBYNAME;
	req->io_Data    = buf;
	req->io_Length  = sizeof(buf);
	req->io_Offset  = (ULONG)name;
	DoIO((struct IORequest *)req);
	say_num("before write, NI_GETBYNAME error = ", (LONG)req->io_Error);

	/* 2. Write it. NOT save mode -- nothing should reach the disk. */
	memset(&h, 0, sizeof(h));
	h.ho_domain  = name;
	h.ho_address = addr;
	h.ho_aliases = NULL;

	req->io_Command = CMD_UPDATE;
	req->io_Data    = (APTR)&h;
	req->io_Length  = sizeof(struct NetInfoHost);
	req->io_Offset  = 0;
	DoIO((struct IORequest *)req);
	say_num("CMD_UPDATE (memory only) error = ", (LONG)req->io_Error);

	/* 3. Read it back. This is the whole experiment. */
	memset(buf, 0, sizeof(buf));
	req->io_Command = NI_GETBYNAME;
	req->io_Data    = buf;
	req->io_Length  = sizeof(buf);
	req->io_Offset  = (ULONG)name;
	DoIO((struct IORequest *)req);
	say_num("after write, NI_GETBYNAME error = ", (LONG)req->io_Error);

	if (req->io_Error == 0)
	{
		struct NetInfoHost *r = (struct NetInfoHost *)buf;
		say("*** WROTE AND READ BACK -- the store is populated through the device ***\n");
		if (r->ho_domain) { say("  ho_domain = "); say((CONST_STRPTR)r->ho_domain); say("\n"); }
	}
	else
	{
		say("no read-back; CMD_UPDATE did not populate a readable entry\n");
	}

	CloseDevice((struct IORequest *)req);
	DeleteIORequest((struct IORequest *)req);
	DeleteMsgPort(mp);
	return RETURN_OK;
}
