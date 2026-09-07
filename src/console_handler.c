/*
 * console_handler -- see console_handler.h.
 *
 * Every branch in here is reachable from tests/test_console_handler.c on the
 * build host. Keep it that way: nothing in this file may call a MorphOS
 * function, because the whole point is that a mistake here can be caught
 * somewhere that a mistake is free.
 */

#include "console_handler.h"

void console_init(struct ConsoleState *st,
                  console_read_fn read_fn,
                  console_write_fn write_fn,
                  void *io_ctx,
                  long initial_handles,
                  long max_packets)
{
	st->read_fn      = read_fn;
	st->write_fn     = write_fn;
	st->io_ctx       = io_ctx;
	st->open_handles = initial_handles;
	st->opens_seen   = initial_handles;
	st->ends_seen    = 0;
	st->packets      = 0;
	st->unknown      = 0;
	st->signal_task  = 0;
	st->signals_seen = 0;
	st->raw_mode     = 0;
	st->draining     = 0;
	st->inconsistent = (initial_handles < 0) ? 1 : 0;
	st->max_packets  = max_packets;
}

void console_begin_drain(struct ConsoleState *st)
{
	st->draining = 1;
}

int console_session_finished(const struct ConsoleState *st)
{
	if (st->inconsistent)
		return 0;	/* we no longer know what is outstanding */

	return (st->open_handles <= 0);
}

int console_safe_to_free_port(const struct ConsoleState *st)
{
	(void)st;

	/* Deliberately unconditional. See the header for the reasoning: this
	 * file must not be the only thing standing between a bug and a dead
	 * machine, so it does not get to authorise the dangerous operation. */
	return 0;
}

static long do_read(struct ConsoleState *st, void *buf, long len)
{
	long n;

	/* Untrusted-ish arguments: a malformed or hostile packet must not
	 * become a wild write. */
	if (buf == NULL || len <= 0)
		return 0;

	if (st->draining)
		return 0;	/* EOF -- the Shell exits on its own */

	if (st->read_fn == NULL)
		return 0;

	n = st->read_fn(st->io_ctx, buf, len);

	/* Trust nothing a callback returns either. */
	if (n < 0)
		n = 0;
	if (n > len)
	{
		n = len;
		st->inconsistent = 1;
	}

	return n;
}

static long do_write(struct ConsoleState *st, const void *buf, long len)
{
	long n;

	if (buf == NULL || len <= 0)
		return 0;

	if (st->write_fn == NULL)
		return len;	/* discard, but tell the Shell it succeeded */

	n = st->write_fn(st->io_ctx, buf, len);

	if (n < 0)
		n = 0;
	if (n > len)
	{
		n = len;
		st->inconsistent = 1;
	}

	return n;
}

struct ConsoleReply console_dispatch(struct ConsoleState *st,
                                     long type,
                                     long arg1,
                                     void *bufarg,
                                     long len)
{
	struct ConsoleReply r;

	r.res1 = DOSFALSE;
	r.res2 = 0;

	st->packets++;
	if (st->max_packets > 0 && st->packets > st->max_packets)
		st->draining = 1;

	switch (type)
	{
	case ACTION_READ:
		r.res1 = do_read(st, bufarg, len);
		break;

	case ACTION_WRITE:
		r.res1 = do_write(st, bufarg, len);
		break;

	case ACTION_WAIT_CHAR:
		/* The Amiga's select(). We always answer "readable": either
		 * bytes are available or the next read reports EOF, and both
		 * complete immediately. Reporting not-readable would park the
		 * Shell for arg1 microseconds for no benefit -- and at EOF it
		 * must wake up in order to exit at all.
		 * A telnetd with a real socket can answer this precisely; that
		 * belongs in the read callback's owner, not here. */
		r.res1 = DOSTRUE;
		break;

	case ACTION_SCREEN_MODE:
		/* arg1: DOSTRUE raw, DOSFALSE cooked. The line discipline. */
		st->raw_mode = (arg1 != DOSFALSE) ? 1 : 0;
		r.res1 = DOSTRUE;
		break;

	case ACTION_FINDINPUT:
	case ACTION_FINDOUTPUT:
	case ACTION_FINDUPDATE:
		/* Someone opened our console by name. The caller wires the
		 * FileHandle up; we only account for it. */
		st->open_handles++;
		st->opens_seen++;
		r.res1 = DOSTRUE;
		break;

	case ACTION_END:
		st->ends_seen++;
		st->open_handles--;
		if (st->open_handles < 0)
		{
			/* More closes than opens: our model of what the Shell
			 * holds is wrong, so we must not conclude anything is
			 * safe from it. */
			st->open_handles = 0;
			st->inconsistent = 1;
		}
		r.res1 = DOSTRUE;
		break;

	case ACTION_CHANGE_SIGNAL:
		/*
		 * dp_Arg1 is the task to signal from now on. Refusing this --
		 * which we did until now, as an unknown packet -- is not
		 * harmless: it is the console telling us who its client is.
		 * Observed on MorphOS 3.20 as the very first packet of a
		 * session and again at teardown.
		 */
		if (arg1 != 0)
			st->signal_task = (void *)arg1;
		st->signals_seen++;
		r.res1 = DOSTRUE;
		break;

	case ACTION_IS_FILESYSTEM:
		r.res1 = DOSFALSE;	/* a console, not a filesystem */
		break;

	case ACTION_SEEK:
	case ACTION_DISK_INFO:
		r.res1 = DOSFALSE;
		r.res2 = ERROR_ACTION_NOT_KNOWN;
		break;

	default:
		st->unknown++;
		r.res1 = DOSFALSE;
		r.res2 = ERROR_ACTION_NOT_KNOWN;
		break;
	}

	return r;
}
