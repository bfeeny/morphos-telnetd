/*
 * contest -- what does a program see when it runs inside a telnet session?
 *
 * Run this THROUGH telnetd, from the remote shell. It answers the two questions
 * that decide whether a full-screen program can work over the network:
 *
 *   1. Does IsInteractive() say yes on our console? A stream that reports
 *      non-interactive is one NewShell would not have accepted at all, and one
 *      that line-oriented tools will treat as a pipe.
 *   2. Does the window-size query come back? CSI SP q (9B 20 71) should be
 *      answered by the handler with CSI 1;1;<rows>;<cols> SP r, built from
 *      whatever NAWS last reported. That is the whole NAWS delivery path,
 *      end to end, from the client's terminal to a program on the far side.
 *
 * The query sequence and the raw-mode dance around it are copied from ixemul's
 * TIOCGWINSZ (ixemul.library/library/__tioctl.c:280-312), which is what any
 * ported program will use.
 */

#include <exec/types.h>
#include <dos/dos.h>
#include <proto/exec.h>
#include <proto/dos.h>

#include <string.h>

static void say(BPTR o, CONST_STRPTR s)
{
	if (o) Write(o, (APTR)s, (LONG)strlen((const char *)s));
}

int main(void)
{
	BPTR in  = Input();
	BPTR out = Output();
	UBYTE req[3];
	char buf[64];
	LONG n, i;

	say(out, "contest: running inside the session\n");

	say(out, "IsInteractive(Input())  = ");
	say(out, IsInteractive(in) ? "TRUE\n" : "FALSE\n");
	say(out, "IsInteractive(Output()) = ");
	say(out, IsInteractive(out) ? "TRUE\n" : "FALSE\n");

	/* Ask the console how big it is. */
	req[0] = 0x9B; req[1] = ' '; req[2] = 'q';
	say(out, "sending CSI SP q ...\n");
	Write(out, req, 3);

	/* ixemul switches to RAW around the read, because in cooked mode the
	 * reply would sit in the line buffer until Enter. */
	SetMode(in, 1);
	memset(buf, 0, sizeof(buf));
	n = Read(in, buf, sizeof(buf) - 1);
	SetMode(in, 0);

	if (n <= 0)
	{
		say(out, "no reply (read returned nothing)\n");
		return RETURN_WARN;
	}

	say(out, "reply bytes: ");
	for (i = 0; i < n; i++)
	{
		char h[8];
		UBYTE c = (UBYTE)buf[i];
		const char *hex = "0123456789ABCDEF";
		h[0] = hex[(c >> 4) & 15]; h[1] = hex[c & 15]; h[2] = ' '; h[3] = 0;
		say(out, (CONST_STRPTR)h);
	}
	say(out, "\n");

	say(out, "reply text : ");
	for (i = 0; i < n; i++)
		if ((UBYTE)buf[i] >= 32 && (UBYTE)buf[i] < 127)
			Write(out, buf + i, 1);
	say(out, "\n");

	return RETURN_OK;
}
