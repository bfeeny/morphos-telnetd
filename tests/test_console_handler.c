/*
 * Host-side tests for the shell-attach packet logic.
 *
 * These run on the BUILD HOST and never on MorphOS. That is the point: this
 * is the code whose failure mode is "the whole OS goes down, taking every
 * other agent's work with it", so it gets exercised somewhere a mistake costs
 * nothing. See "The testing rule" in the vault: never let the thing under test
 * be the only guard between a test and a destroyed machine.
 *
 * Build and run with tests/run.sh.
 */

#include "../src/console_handler.h"

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

/* ---- fake I/O ---------------------------------------------------------- */

struct FakeIO
{
	const char *in;
	long        in_len;
	long        in_pos;

	char        out[4096];
	long        out_len;

	long        force_read_return;	/* if non-zero, return this instead */
};

static long fake_read(void *ctx, void *buf, long len)
{
	struct FakeIO *io = (struct FakeIO *)ctx;
	long avail, n;

	if (io->force_read_return != 0)
		return io->force_read_return;

	avail = io->in_len - io->in_pos;
	if (avail <= 0)
		return 0;

	n = (len < avail) ? len : avail;
	memcpy(buf, io->in + io->in_pos, (size_t)n);
	io->in_pos += n;
	return n;
}

static long fake_write(void *ctx, const void *buf, long len)
{
	struct FakeIO *io = (struct FakeIO *)ctx;
	long space = (long)sizeof(io->out) - io->out_len;
	long n = (len < space) ? len : space;

	if (n > 0) {
		memcpy(io->out + io->out_len, buf, (size_t)n);
		io->out_len += n;
	}
	return len;	/* claim we took it all, as a console would */
}

static void setup(struct ConsoleState *st, struct FakeIO *io, const char *input)
{
	memset(io, 0, sizeof(*io));
	io->in     = input;
	io->in_len = input ? (long)strlen(input) : 0;

	/* 2 == SYS_Input + SYS_Output, the handles SYS_Asynch will close. */
	console_init(st, fake_read, fake_write, io, 2, 20000);
}

/* ---- tests ------------------------------------------------------------- */

static void test_read_delivers_input(void)
{
	struct ConsoleState st;
	struct FakeIO io;
	char buf[64];
	struct ConsoleReply r;

	printf("read delivers input, then EOF\n");
	setup(&st, &io, "version\n");

	memset(buf, 0, sizeof(buf));
	r = console_dispatch(&st, ACTION_READ, 1, buf, (long)sizeof(buf));
	CHECK(r.res1 == 8, "read returns the byte count");
	CHECK(memcmp(buf, "version\n", 8) == 0, "read delivers the right bytes");

	r = console_dispatch(&st, ACTION_READ, 1, buf, (long)sizeof(buf));
	CHECK(r.res1 == 0, "read reports EOF once input is exhausted");
}

static void test_read_rejects_bad_arguments(void)
{
	struct ConsoleState st;
	struct FakeIO io;
	char buf[16];
	struct ConsoleReply r;

	printf("read refuses malformed packets instead of writing wild\n");
	setup(&st, &io, "abc");

	r = console_dispatch(&st, ACTION_READ, 1, NULL, 16);
	CHECK(r.res1 == 0, "NULL buffer yields 0, not a crash");

	r = console_dispatch(&st, ACTION_READ, 1, buf, 0);
	CHECK(r.res1 == 0, "zero length yields 0");

	r = console_dispatch(&st, ACTION_READ, 1, buf, -4096);
	CHECK(r.res1 == 0, "negative length yields 0");
}

static void test_read_never_exceeds_the_buffer(void)
{
	struct ConsoleState st;
	struct FakeIO io;
	char buf[8];
	struct ConsoleReply r;

	printf("a lying read callback cannot overflow the caller's buffer\n");
	setup(&st, &io, "plenty of input here");
	io.force_read_return = 9999;	/* callback claims far too much */

	r = console_dispatch(&st, ACTION_READ, 1, buf, (long)sizeof(buf));
	CHECK(r.res1 == (long)sizeof(buf), "result is clamped to the buffer size");
	CHECK(st.inconsistent == 1, "and the state is marked inconsistent");
}

static void test_write_forwards_output(void)
{
	struct ConsoleState st;
	struct FakeIO io;
	struct ConsoleReply r;

	printf("write forwards the shell's output\n");
	setup(&st, &io, "");

	r = console_dispatch(&st, ACTION_WRITE, 2, (void *)"hello", 5);
	CHECK(r.res1 == 5, "write returns the length");
	CHECK(io.out_len == 5 && memcmp(io.out, "hello", 5) == 0,
	      "the bytes reach the sink");

	r = console_dispatch(&st, ACTION_WRITE, 2, NULL, 5);
	CHECK(r.res1 == 0, "NULL buffer yields 0");
}

static void test_screen_mode_records_line_discipline(void)
{
	struct ConsoleState st;
	struct FakeIO io;
	struct ConsoleReply r;

	printf("SCREEN_MODE is recorded (raw vs cooked)\n");
	setup(&st, &io, "");

	r = console_dispatch(&st, ACTION_SCREEN_MODE, DOSTRUE, NULL, 0);
	CHECK(r.res1 == DOSTRUE, "accepted");
	CHECK(st.raw_mode == 1, "raw mode recorded");

	console_dispatch(&st, ACTION_SCREEN_MODE, DOSFALSE, NULL, 0);
	CHECK(st.raw_mode == 0, "cooked mode recorded");
}

static void test_unknown_packets_are_refused_politely(void)
{
	struct ConsoleState st;
	struct FakeIO io;
	struct ConsoleReply r;

	printf("unknown packets are refused, not ignored\n");
	setup(&st, &io, "");

	r = console_dispatch(&st, 31337, 0, NULL, 0);
	CHECK(r.res1 == DOSFALSE, "refused");
	CHECK(r.res2 == ERROR_ACTION_NOT_KNOWN, "with the documented error");
	CHECK(st.unknown == 1, "and counted, so the probe can report it");
}

/* ---- the ones that actually matter ------------------------------------- */

static void test_session_not_finished_while_handles_are_open(void)
{
	struct ConsoleState st;
	struct FakeIO io;

	printf("session is not finished while the shell holds handles\n");
	setup(&st, &io, "");

	CHECK(!console_session_finished(&st), "two handles outstanding: not finished");

	console_dispatch(&st, ACTION_END, 1, NULL, 0);
	CHECK(!console_session_finished(&st), "one handle outstanding: not finished");

	console_dispatch(&st, ACTION_END, 2, NULL, 0);
	CHECK(console_session_finished(&st), "all closed: finished");
}

static void test_opens_are_counted_so_we_do_not_finish_early(void)
{
	struct ConsoleState st;
	struct FakeIO io;

	printf("a console opened mid-session delays completion\n");
	setup(&st, &io, "");

	/* The Shell opens "*" -- e.g. a program asking for the console. */
	console_dispatch(&st, ACTION_FINDINPUT, 0, NULL, 0);
	CHECK(st.open_handles == 3, "three handles now outstanding");

	console_dispatch(&st, ACTION_END, 0, NULL, 0);
	console_dispatch(&st, ACTION_END, 0, NULL, 0);
	CHECK(!console_session_finished(&st),
	      "still one open: must not declare the session over");

	console_dispatch(&st, ACTION_END, 0, NULL, 0);
	CHECK(console_session_finished(&st), "now it is over");
}

static void test_unbalanced_close_poisons_the_accounting(void)
{
	struct ConsoleState st;
	struct FakeIO io;

	printf("more closes than opens is treated as loss of tracking\n");
	setup(&st, &io, "");

	console_dispatch(&st, ACTION_END, 0, NULL, 0);
	console_dispatch(&st, ACTION_END, 0, NULL, 0);
	console_dispatch(&st, ACTION_END, 0, NULL, 0);	/* one too many */

	CHECK(st.inconsistent == 1, "flagged inconsistent");
	CHECK(!console_session_finished(&st),
	      "and never reports finished again -- we no longer know what is live");
}

static void test_port_is_never_declared_safe_to_free(void)
{
	struct ConsoleState st;
	struct FakeIO io;

	printf("the port is NEVER declared safe to free (the one fatal mistake)\n");
	setup(&st, &io, "");

	CHECK(!console_safe_to_free_port(&st), "not at the start");

	console_dispatch(&st, ACTION_END, 0, NULL, 0);
	console_dispatch(&st, ACTION_END, 0, NULL, 0);
	CHECK(console_session_finished(&st), "session is finished...");
	CHECK(!console_safe_to_free_port(&st),
	      "...and the port is STILL not safe to free");

	st.inconsistent = 1;
	CHECK(!console_safe_to_free_port(&st), "nor when inconsistent");
}

static void test_draining_makes_the_shell_exit(void)
{
	struct ConsoleState st;
	struct FakeIO io;
	char buf[64];
	struct ConsoleReply r;

	printf("draining feeds EOF so the shell leaves of its own accord\n");
	setup(&st, &io, "lots of input still left");

	console_begin_drain(&st);

	r = console_dispatch(&st, ACTION_READ, 1, buf, (long)sizeof(buf));
	CHECK(r.res1 == 0, "read reports EOF even though input remains");

	r = console_dispatch(&st, ACTION_WAIT_CHAR, 1000000, NULL, 0);
	CHECK(r.res1 == DOSTRUE,
	      "WAIT_CHAR still says readable, or the shell would block forever");
}

static void test_packet_cap_triggers_drain(void)
{
	struct ConsoleState st;
	struct FakeIO io;
	char buf[8];
	int i;

	printf("the packet cap winds the session down instead of spinning\n");
	memset(&io, 0, sizeof(io));
	io.in = "x"; io.in_len = 1;
	console_init(&st, fake_read, fake_write, &io, 2, 5);

	for (i = 0; i < 10; i++)
		console_dispatch(&st, ACTION_WAIT_CHAR, 0, buf, 0);

	CHECK(st.draining == 1, "draining after exceeding the cap");
}

/* ---- main -------------------------------------------------------------- */

int main(void)
{
	printf("shell-attach packet logic -- host tests\n\n");

	test_read_delivers_input();
	test_read_rejects_bad_arguments();
	test_read_never_exceeds_the_buffer();
	test_write_forwards_output();
	test_screen_mode_records_line_discipline();
	test_unknown_packets_are_refused_politely();
	test_session_not_finished_while_handles_are_open();
	test_opens_are_counted_so_we_do_not_finish_early();
	test_unbalanced_close_poisons_the_accounting();
	test_port_is_never_declared_safe_to_free();
	test_draining_makes_the_shell_exit();
	test_packet_cap_triggers_drain();

	printf("\n%d checks, %d failures\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
