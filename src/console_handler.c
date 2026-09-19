/*
 * console_handler -- see console_handler.h.
 *
 * Every branch in here is reachable from tests/test_console_handler.c on the
 * build host. Keep it that way: nothing in this file may call a MorphOS
 * function, because the whole point is that a mistake here can be caught
 * somewhere that a mistake is free.
 */

#include "console_handler.h"

/* Distinguishable from any real byte count; never escapes this file. */
#define CONSOLE_WOULD_BLOCK (-12345L)

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
	st->signal_port  = 0;
	st->signals_seen = 0;
	st->session_mode_asks = 0;
	/*
	 * A DEFAULT SIZE, not "unknown".
	 *
	 * Answering CSI SP q with silence is not a benign degradation: the
	 * program that asked blocks forever waiting for a reply, and takes the
	 * session with it. Measured with a client that offers no
	 * NAWS at all -- the shell never came back.
	 *
	 * 80x24 is ixemul's own fallback and what every ported program already
	 * expects. A wrong size is recoverable; a hang is not.
	 */
	st->rows         = 24;
	st->cols         = 80;
	st->pending_len  = 0;
	st->pending_pos  = 0;
	st->q_state      = 0;
	st->size_requests = 0;
	st->established  = 0;
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

	/*
	 * A session is only over once the Shell has opened a console of its own
	 * AND released everything. Before that, a zero count just means the
	 * launcher handed its handles back -- see `established` in the header.
	 *
	 * A session that never establishes is ended by the caller's idle
	 * timeout instead, so this cannot hang forever.
	 */
	if (!st->established)
		return 0;

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

void console_set_window_size(struct ConsoleState *st, long rows, long cols)
{
	if (rows > 0) st->rows = rows;
	if (cols > 0) st->cols = cols;
}

/* Append a decimal number to the pending reply. */
static void pend_num(struct ConsoleState *st, long v)
{
	unsigned char tmp[12];
	int i = 0;

	if (v <= 0) v = 0;
	do { tmp[i++] = (unsigned char)('0' + (v % 10)); v /= 10; } while (v > 0 && i < 12);
	while (i > 0 && st->pending_len < (long)sizeof(st->pending))
		st->pending[st->pending_len++] = tmp[--i];
}

static void pend_byte(struct ConsoleState *st, unsigned char c)
{
	if (st->pending_len < (long)sizeof(st->pending))
		st->pending[st->pending_len++] = c;
}

/*
 * Queue the answer to CSI SP q:  CSI 1;1;<rows>;<cols> SP r
 *
 * "1;1;" is a literal prefix -- the top-left of the reported bounds -- and
 * only the last two numbers vary. Rows first. The space before 'r' is part of
 * the format ixemul's sscanf expects; without it the parse fails.
 */
static void queue_size_report(struct ConsoleState *st)
{
	st->size_requests++;

	if (st->rows <= 0 || st->cols <= 0)
		return;	/* size unknown: say nothing rather than lie */

	/* Drop anything unread rather than interleave two reports. */
	st->pending_len = 0;
	st->pending_pos = 0;

	pend_byte(st, 0x9B);
	pend_byte(st, '1'); pend_byte(st, ';');
	pend_byte(st, '1'); pend_byte(st, ';');
	pend_num(st, st->rows);
	pend_byte(st, ';');
	pend_num(st, st->cols);
	pend_byte(st, ' ');
	pend_byte(st, 'r');
}

/*
 * Forward outgoing bytes, swallowing any CSI SP q request and queueing its
 * reply.
 *
 * This does NOT modify the caller's buffer. On an ACTION_WRITE that buffer
 * belongs to the Shell and may live in read-only memory -- compacting it in
 * place cost a bus error the first time, caught on the build host rather than
 * on a machine with no memory protection.
 *
 * Instead the buffer is forwarded in runs, skipping the request bytes. Held-back
 * bytes from a partial match are emitted from a literal, since we know exactly
 * what they were.
 *
 * Incremental on purpose: the three bytes can arrive in three separate writes.
 * A scanner that only inspects whole buffers will eventually miss one -- the
 * same mistake busybox's telnetd makes with split IAC sequences.
 */
static const unsigned char CSI_SP[2] = { 0x9B, ' ' };

static long emit(struct ConsoleState *st, const unsigned char *p, long n)
{
	if (n <= 0)
		return 0;
	if (st->write_fn == NULL)
		return n;
	return st->write_fn(st->io_ctx, p, n);
}

static void forward_filtered(struct ConsoleState *st,
                             const unsigned char *buf, long len)
{
	long i, run = 0;

	for (i = 0; i < len; i++)
	{
		unsigned char c = buf[i];

		if (st->q_state == 0)
		{
			if (c == 0x9B)
			{
				emit(st, buf + run, i - run);	/* flush text so far */
				st->q_state = 1;
				run = i + 1;
			}
			continue;
		}

		if (st->q_state == 1)
		{
			if (c == ' ') { st->q_state = 2; run = i + 1; continue; }
			emit(st, CSI_SP, 1);	/* the CSI we held back */
			st->q_state = (c == 0x9B) ? 1 : 0;
			run = (c == 0x9B) ? i + 1 : i;
			continue;
		}

		/* q_state == 2 */
		if (c == 'q')
		{
			queue_size_report(st);
			st->q_state = 0;
			run = i + 1;
			continue;
		}
		emit(st, CSI_SP, 2);	/* CSI and space, neither of them ours */
		st->q_state = (c == 0x9B) ? 1 : 0;
		run = (c == 0x9B) ? i + 1 : i;
	}

	if (st->q_state == 0)
		emit(st, buf + run, len - run);
}

static long do_read(struct ConsoleState *st, void *buf, long len)
{
	long n;

	/* Untrusted-ish arguments: a malformed or hostile packet must not
	 * become a wild write. */
	if (buf == NULL || len <= 0)
		return 0;

	/* A queued size report outranks ordinary input: the program that asked
	 * is blocked waiting for it. */
	if (st->pending_pos < st->pending_len)
	{
		long avail = st->pending_len - st->pending_pos;
		unsigned char *dst = (unsigned char *)buf;

		n = (len < avail) ? len : avail;
		for (avail = 0; avail < n; avail++)
			dst[avail] = st->pending[st->pending_pos++];

		if (st->pending_pos >= st->pending_len)
		{
			st->pending_len = 0;
			st->pending_pos = 0;
		}
		return n;
	}

	if (st->draining)
		return 0;	/* EOF -- the Shell exits on its own */

	if (st->read_fn == NULL)
		return 0;

	n = st->read_fn(st->io_ctx, buf, len);

	if (n < 0)
		return 0;	/* real EOF: the peer is gone, let the Shell exit */
	if (n == 0)
		return CONSOLE_WOULD_BLOCK;	/* hold the packet instead */

	if (n > len)
	{
		n = len;
		st->inconsistent = 1;
	}

	return n;
}

static long do_write(struct ConsoleState *st, const void *buf, long len)
{
	if (buf == NULL || len <= 0)
		return 0;

	forward_filtered(st, (const unsigned char *)buf, len);

	/* Always report the full count. We consumed everything the Shell gave
	 * us, including any request we swallowed; a short count reads as an
	 * error to the caller. */
	return len;
}

struct ConsoleReply console_dispatch(struct ConsoleState *st,
                                     long type,
                                     long arg1,
                                     long arg2,
                                     void *bufarg,
                                     long len)
{
	struct ConsoleReply r;

	r.res1  = DOSFALSE;
	r.res2  = 0;
	r.defer = 0;

	st->packets++;
	if (st->max_packets > 0 && st->packets > st->max_packets)
		st->draining = 1;

	switch (type)
	{
	case ACTION_READ:
		r.res1 = do_read(st, bufarg, len);
		if (r.res1 == CONSOLE_WOULD_BLOCK)
		{
			r.res1  = 0;
			r.defer = 1;
		}
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
		st->established = 1;	/* the Shell has a console of its own now */
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

	case ACTION_SESSION_MODE:
		/*
		 * "Are you a linux compatible console handler?" -- ixemul's
		 * private packet, asked once per stream at startup.
		 *
		 * ANSWERING NO CORRUPTS OUTPUT IN RAW MODE. ixemul sets
		 * IXTTY_SPECIAL only if BOTH dp_Res1 AND dp_Res2 come back
		 * DOSTRUE (_cli_parse.c:216), and without that flag __write.c
		 * substitutes 0x84 -- the Amiga console's INDEX control -- for
		 * every newline once a program clears ONLCR/OPOST:
		 *
		 *   if ((!(f->f_ttyflags & IXTTY_SPECIAL)) && ...)
		 *       tmp = __do_sync_write(f, "\204", 1);
		 *
		 * Clearing ONLCR is what a full-screen or line-editing program
		 * does, so the failure appears exactly where it is hardest to
		 * notice by hand, and a telnet client receives 0x84 where it
		 * expects LF. On a real Amiga console 0x84 is correct; over a
		 * socket whose far end is a real terminal it is garbage.
		 *
		 * We are "linux compatible" in precisely the sense meant: bytes
		 * go to a stream whose other end wants LF. Source and reasoning
		 * read out of the ixemul source.
		 */
		st->session_mode_asks++;
		r.res1 = DOSTRUE;
		r.res2 = DOSTRUE;	/* BOTH, or the flag is not set */
		break;

	case ACTION_CHANGE_SIGNAL:
		/*
		 * dp_Arg2 is the MsgPort of the process to signal on ^C. Keep
		 * it; the eventual break path is
		 *     Signal(((struct MsgPort *)port)->mp_SigTask, SIGBREAKF_CTRL_C)
		 * and the same packet governs ^C, ^D, ^E and ^F.
		 */
		if (arg2 != 0)
			st->signal_port = (void *)arg2;
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
