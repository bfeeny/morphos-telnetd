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
	test_opening_offer();

	printf("\n%d checks, %d failures\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
