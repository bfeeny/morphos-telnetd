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
};

void telnet_init(struct TelnetState *ts,
                 telnet_out_fn out_fn,
                 telnet_size_fn size_fn,
                 void *ctx);

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
