/*
 * telnet.h -- RFC 854 front end. See telnet.c.
 *
 * Knows nothing about MorphOS. Turns a telnet stream into plain bytes plus a
 * window size, and plain bytes back into a telnet stream.
 */

#ifndef TELNET_H
#define TELNET_H

#define TELNET_SB_MAX 64	/* bounded; a subnegotiation cannot grow past this */

enum TelnetParseState
{
	TS_DATA = 0,
	TS_CR,		/* saw a CR: the next byte decides what it meant */
	TS_IAC,
	TS_VERB,
	TS_SB_OPT,
	TS_SB_DATA,
	TS_SB_IAC
};

/* Send bytes to the network. */
typedef void (*telnet_out_fn)(void *ctx, const unsigned char *buf, long len);

/* The client told us its window size (NAWS). Rows, then columns. */
typedef void (*telnet_size_fn)(void *ctx, long rows, long cols);

struct TelnetState
{
	telnet_out_fn  out_fn;
	telnet_size_fn size_fn;
	void          *ctx;

	int  state;
	unsigned char pending_verb;

	unsigned char sb_opt;
	unsigned char sb_buf[TELNET_SB_MAX];
	long          sb_len;
	int           sb_overflow;

	long commands;	/* how many IAC sequences we have seen */

	/*
	 * Per-option state, RFC 1143's three values.
	 *
	 * OPT_NO      not in effect
	 * OPT_WANTYES we asked and have not been answered
	 * OPT_YES     in effect
	 *
	 * Two of these are about US (do we echo, do we suppress go-ahead) and
	 * two are about HIM (does he send window size, terminal type). The
	 * distinction decides whether an arriving DONT is an ANSWER to our own
	 * request -- which needs no reply -- or a DEMAND to stop something we
	 * are currently doing, which RFC 854 says must always be accepted.
	 * Without the state those are indistinguishable, which is why they used
	 * to be ignored.
	 */
	unsigned char us_echo, us_sga;	/* options we perform */
	unsigned char him_naws, him_ttype;	/* options he performs */

	/* Outbound: a CR whose successor decides what it meant. See
	 * telnet_output(); it cannot span a call, so it is flushed as a bare
	 * CR rather than delaying output that may be a live prompt. */
	int  out_cr_held;
};

void telnet_init(struct TelnetState *ts,
                 telnet_out_fn out_fn,
                 telnet_size_fn size_fn,
                 void *ctx);

#define OPT_NO       0
#define OPT_WANTYES  1
#define OPT_YES      2

/*
 * May we echo what the client types?
 *
 * We offer WILL ECHO and start echoing at once, so a password is hidden simply
 * by choosing not to echo it. But a client is entitled to send DONT ECHO, and
 * once it has, echoing anyway gives it doubled characters it cannot stop.
 */
int telnet_should_echo(const struct TelnetState *ts);

/* Send our opening option offers. Call once, on connect. */
void telnet_start(struct TelnetState *ts);

/*
 * Feed bytes from the network. Writes the plain data into `out` and returns
 * how many bytes that was; option negotiation is consumed and answered along
 * the way. Safe to call with any split of the stream.
 */
long telnet_input(struct TelnetState *ts,
                  const unsigned char *in, long len,
                  unsigned char *out, long out_max);

/* Send program output to the network, escaping any literal 255. */
void telnet_output(struct TelnetState *ts, const unsigned char *buf, long len);

#endif /* TELNET_H */
