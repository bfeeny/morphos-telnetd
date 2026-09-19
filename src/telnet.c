/*
 * telnet.c -- the protocol front end: RFC 854 and the options we care about.
 *
 * This is the replaceable half of the daemon. It knows nothing about MorphOS,
 * DOS packets or shells; it turns a telnet byte stream into plain bytes plus a
 * window size, and plain bytes back into a telnet byte stream. An sshd would
 * delete this file and keep everything else.
 *
 * The parser is a byte-at-a-time state machine that can be suspended at any
 * byte. That is not fastidiousness: TCP does not respect message boundaries, so
 * a sequence can arrive split across reads. busybox's telnetd peeks at buf[1],
 * buf[2], buf[3] instead, and carries three bugs because of it -- a NAWS
 * subnegotiation split across two reads is silently dropped, with a literal
 * "BUG: incomplete, can't process" in its source.
 */

#include "telnet.h"

/* RFC 854 */
#define IAC   255
#define DONT  254
#define DO    253
#define WONT  252
#define WILL  251
#define SB    250
#define SE    240

/* Options we implement */
#define OPT_ECHO   1
#define OPT_SGA    3	/* suppress go-ahead: character-at-a-time */
#define OPT_TTYPE 24
#define OPT_NAWS  31

void telnet_init(struct TelnetState *ts,
                 telnet_out_fn out_fn,
                 telnet_size_fn size_fn,
                 void *ctx)
{
	ts->out_fn  = out_fn;
	ts->size_fn = size_fn;
	ts->ctx     = ctx;
	ts->state   = TS_DATA;
	ts->sb_opt  = 0;
	ts->sb_len  = 0;
	ts->sb_overflow = 0;
	ts->commands = 0;
	ts->out_cr_held = 0;
	ts->us_echo = ts->us_sga = OPT_NO;
	ts->him_naws = ts->him_ttype = OPT_NO;
}

int telnet_should_echo(const struct TelnetState *ts)
{
	/* WANTYES counts as yes: we echo from the moment we offer, and only
	 * stop if the client actually objects. */
	return ts->us_echo != OPT_NO;
}

static void raw_out(struct TelnetState *ts, const unsigned char *b, long n)
{
	if (ts->out_fn && n > 0)
		ts->out_fn(ts->ctx, b, n);
}

/*
 * The opening position. Deliberately short.
 *
 * We echo, so the client must not; SGA gives character-at-a-time, which is what
 * an interactive shell needs; NAWS is the whole reason full-screen tools will
 * work. We do not offer LINEMODE -- line editing belongs to the Shell.
 */
void telnet_start(struct TelnetState *ts)
{
	static const unsigned char hello[] = {
		IAC, WILL, OPT_ECHO,
		IAC, WILL, OPT_SGA,
		IAC, DO,   OPT_NAWS,
		IAC, DO,   OPT_TTYPE
	};

	raw_out(ts, hello, (long)sizeof(hello));

	ts->us_echo   = OPT_WANTYES;
	ts->us_sga    = OPT_WANTYES;
	ts->him_naws  = OPT_WANTYES;
	ts->him_ttype = OPT_WANTYES;
}

/* Defined below; declared here because the negotiation table uses it. */
static void refuse(struct TelnetState *ts, unsigned char verb, unsigned char opt);

/* Which state variable, if any, tracks this option? */
static unsigned char *us_slot(struct TelnetState *ts, unsigned char opt)
{
	if (opt == OPT_ECHO) return &ts->us_echo;
	if (opt == OPT_SGA)  return &ts->us_sga;
	return 0;
}

static unsigned char *him_slot(struct TelnetState *ts, unsigned char opt)
{
	if (opt == OPT_NAWS)  return &ts->him_naws;
	if (opt == OPT_TTYPE) return &ts->him_ttype;
	return 0;
}

/*
 * RFC 1143 §3, reduced to the four options this daemon implements.
 *
 * The rule that used to be missing is RFC 854 p.3: a request to DISABLE must
 * always be accepted. DONT and WONT were ignored entirely, so a client that
 * sent DONT ECHO got no WONT back, we carried on echoing, and a Q-method client
 * sat in WANTNO waiting for a reply that never came -- doubled characters, and
 * no way for it to recover.
 *
 * The state is what makes a correct answer possible: an arriving DONT is either
 * an ANSWER to a WILL we sent (no reply -- replying would negotiate in circles)
 * or a DEMAND to stop something already in effect (reply WONT). Those look
 * identical on the wire and differ only in what we know.
 */
static void negotiate(struct TelnetState *ts, unsigned char verb, unsigned char opt)
{
	unsigned char *mine = us_slot(ts, opt);
	unsigned char *his  = him_slot(ts, opt);

	switch (verb)
	{
	case DO:
		if (!mine)			/* not ours to perform */
		{
			refuse(ts, WONT, opt);
			return;
		}
		if (*mine == OPT_WANTYES)  *mine = OPT_YES;	/* our offer, agreed */
		else if (*mine == OPT_NO)			/* unsolicited ask */
		{
			*mine = OPT_YES;
			refuse(ts, WILL, opt);			/* accept it */
		}
		/* already YES: silence, or we negotiate in circles */
		break;

	case DONT:
		if (!mine)
			return;		/* not doing it; nothing to turn off */
		if (*mine == OPT_YES)
		{
			*mine = OPT_NO;
			refuse(ts, WONT, opt);	/* a demand: must be accepted */
		}
		else if (*mine == OPT_WANTYES)
			*mine = OPT_NO;		/* an answer: no reply */
		break;

	case WILL:
		if (!his)
		{
			refuse(ts, DONT, opt);
			return;
		}
		if (*his == OPT_WANTYES) *his = OPT_YES;
		else if (*his == OPT_NO)
		{
			*his = OPT_YES;
			refuse(ts, DO, opt);
		}
		break;

	case WONT:
		if (!his)
			return;
		if (*his == OPT_YES)
		{
			*his = OPT_NO;
			refuse(ts, DONT, opt);
		}
		else if (*his == OPT_WANTYES)
			*his = OPT_NO;
		break;
	}
}

/* Refuse anything we did not ask for, rather than ignoring it. A client that
 * gets no answer may wait; a client told DONT/WONT moves on. */
static void refuse(struct TelnetState *ts, unsigned char verb, unsigned char opt)
{
	unsigned char r[3];

	r[0] = IAC;
	r[1] = verb;
	r[2] = opt;
	raw_out(ts, r, 3);
}

static void handle_subnegotiation(struct TelnetState *ts)
{
	if (ts->sb_overflow)
		return;	/* truncated: acting on half a message is worse than ignoring it */

	if (ts->sb_opt == OPT_NAWS && ts->sb_len >= 4)
	{
		/* IAC SB NAWS <col_hi> <col_lo> <row_hi> <row_lo> IAC SE
		 * Columns first, big-endian. RFC 1073. */
		long cols = ((long)ts->sb_buf[0] << 8) | ts->sb_buf[1];
		long rows = ((long)ts->sb_buf[2] << 8) | ts->sb_buf[3];

		if (ts->size_fn && rows > 0 && cols > 0)
			ts->size_fn(ts->ctx, rows, cols);
	}
}

long telnet_input(struct TelnetState *ts,
                  const unsigned char *in, long len,
                  unsigned char *out, long out_max)
{
	long i, n = 0;

	for (i = 0; i < len; i++)
	{
		unsigned char c = in[i];

		switch (ts->state)
		{
		case TS_DATA:
			if (c == IAC) { ts->state = TS_IAC; break; }
			if (c == '\r') { ts->state = TS_CR; break; }
			if (n < out_max) out[n++] = c;
			break;

		case TS_CR:
			/*
			 * RFC 854: on the wire a line ends with CR LF, and a
			 * BARE carriage return is sent as CR NUL. So the CR is
			 * an escape, not data, and passing it through hands the
			 * Shell "version\r" -- which it correctly rejects as an
			 * unknown command. This is why every typed command came
			 * back as "Unknown command".
			 */
			ts->state = TS_DATA;
			if (c == '\n')                      /* CR LF -> newline */
			{
				if (n < out_max) out[n++] = '\n';
			}
			else if (c == '\0')                 /* CR NUL -> bare CR */
			{
				if (n < out_max) out[n++] = '\r';
			}
			else if (c == IAC)                  /* CR then a command */
			{
				if (n < out_max) out[n++] = '\n';
				ts->state = TS_IAC;
			}
			else                                /* lone CR: treat as newline */
			{
				if (n < out_max) out[n++] = '\n';
				if (c == '\r') { ts->state = TS_CR; break; }
				if (n < out_max) out[n++] = c;
			}
			break;

		case TS_IAC:
			ts->commands++;
			if (c == IAC)		/* escaped literal 255 */
			{
				if (n < out_max) out[n++] = c;
				ts->state = TS_DATA;
			}
			else if (c == WILL || c == WONT || c == DO || c == DONT)
			{
				ts->pending_verb = c;
				ts->state = TS_VERB;
			}
			else if (c == SB)
			{
				ts->state = TS_SB_OPT;
			}
			else
			{
				ts->state = TS_DATA;	/* NOP, GA, and friends */
			}
			break;

		case TS_VERB:
			negotiate(ts, ts->pending_verb, c);
			ts->state = TS_DATA;
			break;

		case TS_SB_OPT:
			ts->sb_opt      = c;
			ts->sb_len      = 0;
			ts->sb_overflow = 0;
			ts->state       = TS_SB_DATA;
			break;

		case TS_SB_DATA:
			if (c == IAC) { ts->state = TS_SB_IAC; break; }
			if (ts->sb_len < TELNET_SB_MAX)
				ts->sb_buf[ts->sb_len++] = c;
			else
				ts->sb_overflow = 1;	/* bounded, and remembered */
			break;

		case TS_SB_IAC:
			if (c == IAC)		/* escaped 255 inside a subnegotiation */
			{
				if (ts->sb_len < TELNET_SB_MAX)
					ts->sb_buf[ts->sb_len++] = c;
				else
					ts->sb_overflow = 1;
				ts->state = TS_SB_DATA;
			}
			else if (c == SE)
			{
				handle_subnegotiation(ts);
				ts->state = TS_DATA;
			}
			else
			{
				ts->state = TS_DATA;	/* malformed; resynchronise */
			}
			break;
		}
	}

	return n;
}

/*
 * Outbound: put program output into NVT form.
 *
 * Three substitutions, and only one of them was here before.
 *
 * A literal 255 must be sent as IAC IAC or the client reads it as a command.
 *
 * A NEWLINE MUST GO OUT AS CR LF. RFC 854 p.11: "the sequence CR LF must be
 * treated as a single new line character". The Shell writes the Amiga
 * convention -- a bare LF -- and this passed it straight through, which was
 * measured on the wire: `version` came back as "...51.66\n" with no CR. A Unix
 * telnetd never has to think about it because the pty's ONLCR does it; we have
 * no pty, so it is ours to do. A client that has cleared ONLCR on its own
 * terminal -- which BSD telnet does once it accepts our WILL ECHO -- staircases
 * without this, each line starting where the last one ended.
 *
 * A BARE CR MUST GO OUT AS CR NUL, same page: "the CR character must be avoided
 * in other contexts". Otherwise a client is entitled to read the next byte as
 * part of a line ending.
 *
 * A CR at the very end of a buffer is emitted as a bare CR rather than held for
 * the next call. Holding it would be more correct and would also delay it, and
 * this buffer may be a prompt somebody is waiting to see; a split CR LF then
 * arrives as CR NUL CR LF, which renders identically.
 */
void telnet_output(struct TelnetState *ts, const unsigned char *buf, long len)
{
	static const unsigned char IACIAC[2] = { IAC, IAC };
	static const unsigned char CRLF[2]   = { '\r', '\n' };
	static const unsigned char CRNUL[2]  = { '\r', '\0' };
	long i, run = 0;

	for (i = 0; i < len; i++)
	{
		unsigned char c = buf[i];

		if (ts->out_cr_held)
		{
			ts->out_cr_held = 0;
			run = i;
			if (c == '\n')
			{
				raw_out(ts, CRLF, 2);	/* CR LF stays CR LF */
				run = i + 1;
				continue;
			}
			raw_out(ts, CRNUL, 2);		/* it was a bare CR */
			/* and c still has to be handled below */
		}

		if (c == '\r')
		{
			raw_out(ts, buf + run, i - run);
			ts->out_cr_held = 1;
			run = i + 1;
		}
		else if (c == '\n')
		{
			raw_out(ts, buf + run, i - run);
			raw_out(ts, CRLF, 2);
			run = i + 1;
		}
		else if (c == IAC)
		{
			raw_out(ts, buf + run, i - run);
			raw_out(ts, IACIAC, 2);
			run = i + 1;
		}
	}

	raw_out(ts, buf + run, len - run);

	if (ts->out_cr_held)
	{
		ts->out_cr_held = 0;
		raw_out(ts, CRNUL, 2);
	}
}
