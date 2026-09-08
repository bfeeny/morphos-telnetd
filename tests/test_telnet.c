/*
 * Host-side tests for the telnet protocol front end.
 *
 * The cases that matter are the split ones: TCP does not respect message
 * boundaries, and a parser that assumes a whole sequence is present will
 * eventually be wrong. busybox's telnetd drops a NAWS subnegotiation split
 * across two reads for exactly that reason.
 */

#include "../src/telnet.h"

#include <stdio.h>
#include <string.h>

static int failures = 0;
static int checks   = 0;

#define CHECK(cond, what)                                                     \
	do {                                                                  \
		checks++;                                                     \
		if (!(cond)) {                                                \
			failures++;                                           \
			printf("  FAIL  %s\n        at %s:%d\n",              \
			       (what), __FILE__, __LINE__);                   \
		}                                                             \
	} while (0)

struct Sink
{
	unsigned char out[512];
	long          out_len;
	long          rows, cols;
	int           size_calls;
};

static void sink_out(void *ctx, const unsigned char *b, long n)
{
	struct Sink *s = (struct Sink *)ctx;
	long i;
	for (i = 0; i < n && s->out_len < (long)sizeof(s->out); i++)
		s->out[s->out_len++] = b[i];
}

static void sink_size(void *ctx, long rows, long cols)
{
	struct Sink *s = (struct Sink *)ctx;
	s->rows = rows;
	s->cols = cols;
	s->size_calls++;
}

static void setup(struct TelnetState *ts, struct Sink *s)
{
	memset(s, 0, sizeof(*s));
	telnet_init(ts, sink_out, sink_size, s);
}

/* ------------------------------------------------------------------ */

static void test_plain_data_passes_through(void)
{
	struct TelnetState ts; struct Sink s;
	unsigned char out[64];
	long n;

	printf("plain data passes through untouched\n");
	setup(&ts, &s);

	n = telnet_input(&ts, (const unsigned char *)"ls -l\n", 6, out, sizeof(out));
	CHECK(n == 6 && memcmp(out, "ls -l\n", 6) == 0, "unchanged");
	CHECK(ts.commands == 0, "no commands seen");
}

static void test_escaped_255_becomes_one_byte(void)
{
	struct TelnetState ts; struct Sink s;
	const unsigned char in[] = { 'a', 255, 255, 'b' };
	unsigned char out[64];
	long n;

	printf("IAC IAC in the input is one literal 255\n");
	setup(&ts, &s);

	n = telnet_input(&ts, in, 4, out, sizeof(out));
	CHECK(n == 3, "three data bytes");
	CHECK(out[0] == 'a' && out[1] == 255 && out[2] == 'b', "the right three");
}

static void test_naws_sets_the_size(void)
{
	struct TelnetState ts; struct Sink s;
	/* IAC SB NAWS 0 120 0 40 IAC SE  -- cols first, big-endian */
	const unsigned char in[] = { 255, 250, 31, 0, 120, 0, 40, 255, 240 };
	unsigned char out[64];
	long n;

	printf("NAWS is decoded: cols first on the wire, rows first to us\n");
	setup(&ts, &s);

	n = telnet_input(&ts, in, sizeof(in), out, sizeof(out));
	CHECK(n == 0, "no data bytes emerge");
	CHECK(s.size_calls == 1, "size reported once");
	CHECK(s.rows == 40 && s.cols == 120, "rows=40 cols=120");
}

static void test_naws_split_across_reads(void)
{
	struct TelnetState ts; struct Sink s;
	const unsigned char in[] = { 255, 250, 31, 0, 120, 0, 40, 255, 240 };
	unsigned char out[64];
	unsigned int i;

	printf("NAWS split one byte per read still decodes (busybox drops this)\n");
	setup(&ts, &s);

	for (i = 0; i < sizeof(in); i++)
		telnet_input(&ts, &in[i], 1, out, sizeof(out));

	CHECK(s.size_calls == 1, "still reported once");
	CHECK(s.rows == 40 && s.cols == 120, "and correctly");
}

static void test_data_around_a_split_command(void)
{
	struct TelnetState ts; struct Sink s;
	const unsigned char a[] = { 'h', 'i', 255 };
	const unsigned char b[] = { 251, 31, '!' };
	unsigned char out[64];
	long n1, n2;

	printf("a command split mid-sequence does not eat the data around it\n");
	setup(&ts, &s);

	n1 = telnet_input(&ts, a, 3, out, sizeof(out));
	CHECK(n1 == 2 && out[0] == 'h' && out[1] == 'i', "data before survives");

	n2 = telnet_input(&ts, b, 3, out, sizeof(out));
	CHECK(n2 == 1 && out[0] == '!', "data after survives");
}

static void test_unwanted_options_are_refused(void)
{
	struct TelnetState ts; struct Sink s;
	const unsigned char in[] = { 255, 251, 34 };	/* WILL LINEMODE */
	unsigned char out[64];

	printf("an option we did not ask for is refused, not ignored\n");
	setup(&ts, &s);

	telnet_input(&ts, in, 3, out, sizeof(out));
	CHECK(s.out_len == 3, "we answered");
	CHECK(s.out[0] == 255 && s.out[1] == 254 && s.out[2] == 34,
	      "IAC DONT LINEMODE");
}

static void test_oversized_subnegotiation_is_bounded(void)
{
	struct TelnetState ts; struct Sink s;
	unsigned char in[TELNET_SB_MAX + 40];
	unsigned char out[256];
	unsigned int i;

	printf("an overlong subnegotiation is bounded and then ignored\n");
	setup(&ts, &s);

	in[0] = 255; in[1] = 250; in[2] = 31;
	for (i = 3; i < sizeof(in) - 2; i++)
		in[i] = 'A';
	in[sizeof(in) - 2] = 255;
	in[sizeof(in) - 1] = 240;

	telnet_input(&ts, in, sizeof(in), out, sizeof(out));
	CHECK(ts.sb_overflow == 1, "overflow noticed");
	CHECK(s.size_calls == 0, "a truncated message is not acted on");
	CHECK(ts.sb_len <= TELNET_SB_MAX, "buffer never exceeded");
}

static void test_output_escapes_255(void)
{
	struct TelnetState ts; struct Sink s;
	const unsigned char buf[] = { 'a', 255, 'b' };

	printf("a literal 255 in program output is escaped on the way out\n");
	setup(&ts, &s);

	telnet_output(&ts, buf, 3);
	CHECK(s.out_len == 4, "one byte became two");
	CHECK(s.out[0] == 'a' && s.out[1] == 255 && s.out[2] == 255
	      && s.out[3] == 'b', "IAC IAC in the middle");
}

/*
 * RFC 854 p.11: "the sequence CR LF must be treated as a single new line
 * character" and "the CR character must be avoided in other contexts".
 *
 * These matter because there is no pty here. A Unix telnetd gets newline
 * translation free from the terminal driver's ONLCR; we are the terminal, so if
 * we do not do it, nobody does -- and it was measured going out wrong: `version`
 * reached the wire as "...51.66\n" with no CR at all.
 */
static void test_output_lf_becomes_crlf(void)
{
	struct TelnetState ts; struct Sink s;

	printf("a bare LF from the Shell goes out as CR LF\n");
	setup(&ts, &s);

	telnet_output(&ts, (const unsigned char *)"hi\n", 3);
	CHECK(s.out_len == 4, "three bytes became four");
	CHECK(s.out[0] == 'h' && s.out[1] == 'i', "the text is untouched");
	CHECK(s.out[2] == '\r' && s.out[3] == '\n', "and the newline is CR LF");
}

static void test_output_crlf_stays_crlf(void)
{
	struct TelnetState ts; struct Sink s;

	printf("our own CR LF is not doubled into CR CR LF\n");
	setup(&ts, &s);

	telnet_output(&ts, (const unsigned char *)"hi\r\n", 4);
	CHECK(s.out_len == 4, "nothing was added");
	CHECK(s.out[2] == '\r' && s.out[3] == '\n', "exactly one CR LF");
}

static void test_output_bare_cr_becomes_cr_nul(void)
{
	struct TelnetState ts; struct Sink s;

	printf("a bare CR goes out as CR NUL, so it cannot start a line ending\n");
	setup(&ts, &s);

	telnet_output(&ts, (const unsigned char *)"a\rb", 3);
	CHECK(s.out_len == 4, "one byte became two");
	CHECK(s.out[0] == 'a' && s.out[1] == '\r' && s.out[2] == '\0'
	      && s.out[3] == 'b', "CR NUL in the middle");
}

static void test_output_trailing_cr_is_not_held(void)
{
	struct TelnetState ts; struct Sink s;

	printf("a CR ending a write is emitted, not held for the next one\n");
	setup(&ts, &s);

	/* Holding it would be more correct and would also delay it -- and this
	 * buffer may be a prompt somebody is waiting to see. */
	telnet_output(&ts, (const unsigned char *)"x\r", 2);
	CHECK(s.out_len == 3, "the CR went out immediately");
	CHECK(s.out[1] == '\r' && s.out[2] == '\0', "as a bare CR");
	CHECK(ts.out_cr_held == 0, "and nothing is left pending");
}

static void test_output_255_and_newline_together(void)
{
	struct TelnetState ts; struct Sink s;
	const unsigned char buf[] = { 255, '\n', 255 };

	printf("escaping and newline translation do not interfere\n");
	setup(&ts, &s);

	telnet_output(&ts, buf, 3);
	CHECK(s.out_len == 6, "two escapes and one added CR");
	CHECK(s.out[0] == 255 && s.out[1] == 255, "leading IAC doubled");
	CHECK(s.out[2] == '\r' && s.out[3] == '\n', "then CR LF");
	CHECK(s.out[4] == 255 && s.out[5] == 255, "trailing IAC doubled");
}

static void test_opening_offer(void)
{
	struct TelnetState ts; struct Sink s;

	printf("the opening negotiation offers echo, SGA, NAWS, TTYPE\n");
	setup(&ts, &s);

	telnet_start(&ts);
	CHECK(s.out_len == 12, "four three-byte commands");
	CHECK(s.out[1] == 251 && s.out[2] == 1,  "WILL ECHO");
	CHECK(s.out[4] == 251 && s.out[5] == 3,  "WILL SGA");
	CHECK(s.out[7] == 253 && s.out[8] == 31, "DO NAWS");
}

static void test_crlf_becomes_newline(void)
{
	struct TelnetState ts; struct Sink s;
	unsigned char out[64];
	long n;

	printf("CR LF becomes a single newline (not CR, which breaks commands)\n");
	setup(&ts, &s);

	n = telnet_input(&ts, (const unsigned char *)"version\r\n", 9, out, sizeof(out));
	CHECK(n == 8, "eight bytes out, not nine");
	CHECK(memcmp(out, "version\n", 8) == 0, "the CR is gone");
}

static void test_cr_nul_is_a_bare_cr(void)
{
	struct TelnetState ts; struct Sink s;
	const unsigned char in[] = { 'a', '\r', 0, 'b' };
	unsigned char out[64];
	long n;

	printf("CR NUL is a bare carriage return, per RFC 854\n");
	setup(&ts, &s);

	n = telnet_input(&ts, in, 4, out, sizeof(out));
	CHECK(n == 3, "three bytes");
	CHECK(out[0]=='a' && out[1]=='\r' && out[2]=='b', "CR survives as CR");
}

static void test_crlf_split_across_reads(void)
{
	struct TelnetState ts; struct Sink s;
	unsigned char out[64];
	long a, b;

	printf("CR and LF arriving in separate reads still make one newline\n");
	setup(&ts, &s);

	a = telnet_input(&ts, (const unsigned char *)"hi\r", 3, out, sizeof(out));
	CHECK(a == 2, "only the data so far");
	b = telnet_input(&ts, (const unsigned char *)"\n", 1, out, sizeof(out));
	CHECK(b == 1 && out[0] == '\n', "the newline arrives with the LF");
}

int main(void)
{
	printf("telnet protocol front end -- host tests\n\n");

	test_plain_data_passes_through();
	test_escaped_255_becomes_one_byte();
	test_naws_sets_the_size();
	test_naws_split_across_reads();
	test_data_around_a_split_command();
	test_unwanted_options_are_refused();
	test_oversized_subnegotiation_is_bounded();
	test_output_escapes_255();
	test_output_lf_becomes_crlf();
	test_output_crlf_stays_crlf();
	test_output_bare_cr_becomes_cr_nul();
	test_output_trailing_cr_is_not_held();
	test_output_255_and_newline_together();
	test_opening_offer();
	test_crlf_becomes_newline();
	test_cr_nul_is_a_bare_cr();
	test_crlf_split_across_reads();

	printf("\n%d checks, %d failures\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
