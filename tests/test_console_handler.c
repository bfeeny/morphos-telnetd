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
	int         eof;		/* exhausted input means EOF, not would-block */
};

static long fake_read(void *ctx, void *buf, long len)
{
	struct FakeIO *io = (struct FakeIO *)ctx;
	long avail, n;

	if (io->force_read_return != 0)
		return io->force_read_return;

	avail = io->in_len - io->in_pos;
	if (avail <= 0)
		return io->eof ? -1 : 0;	/* -1 EOF, 0 would-block */

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
	io->eof    = 1;	/* most tests want classic EOF behaviour */

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
	r = console_dispatch(&st, ACTION_READ, 1, 0, buf, (long)sizeof(buf));
	CHECK(r.res1 == 8, "read returns the byte count");
	CHECK(memcmp(buf, "version\n", 8) == 0, "read delivers the right bytes");

	r = console_dispatch(&st, ACTION_READ, 1, 0, buf, (long)sizeof(buf));
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

	r = console_dispatch(&st, ACTION_READ, 1, 0, NULL, 16);
	CHECK(r.res1 == 0, "NULL buffer yields 0, not a crash");

	r = console_dispatch(&st, ACTION_READ, 1, 0, buf, 0);
	CHECK(r.res1 == 0, "zero length yields 0");

	r = console_dispatch(&st, ACTION_READ, 1, 0, buf, -4096);
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

	r = console_dispatch(&st, ACTION_READ, 1, 0, buf, (long)sizeof(buf));
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

	r = console_dispatch(&st, ACTION_WRITE, 2, 0, (void *)"hello", 5);
	CHECK(r.res1 == 5, "write returns the length");
	CHECK(io.out_len == 5 && memcmp(io.out, "hello", 5) == 0,
	      "the bytes reach the sink");

	r = console_dispatch(&st, ACTION_WRITE, 2, 0, NULL, 5);
	CHECK(r.res1 == 0, "NULL buffer yields 0");
}

static void test_screen_mode_records_line_discipline(void)
{
	struct ConsoleState st;
	struct FakeIO io;
	struct ConsoleReply r;

	printf("SCREEN_MODE is recorded (raw vs cooked)\n");
	setup(&st, &io, "");

	r = console_dispatch(&st, ACTION_SCREEN_MODE, DOSTRUE, 0, NULL, 0);
	CHECK(r.res1 == DOSTRUE, "accepted");
	CHECK(st.raw_mode == 1, "raw mode recorded");

	console_dispatch(&st, ACTION_SCREEN_MODE, DOSFALSE, 0, NULL, 0);
	CHECK(st.raw_mode == 0, "cooked mode recorded");
}

static void test_unknown_packets_are_refused_politely(void)
{
	struct ConsoleState st;
	struct FakeIO io;
	struct ConsoleReply r;

	printf("unknown packets are refused, not ignored\n");
	setup(&st, &io, "");

	r = console_dispatch(&st, 31337, 0, 0, NULL, 0);
	CHECK(r.res1 == DOSFALSE, "refused");
	CHECK(r.res2 == ERROR_ACTION_NOT_KNOWN, "with the documented error");
	CHECK(st.unknown == 1, "and counted, so the probe can report it");
}

static void test_change_signal_is_accepted_and_recorded(void)
{
	struct ConsoleState st;
	struct FakeIO io;
	struct ConsoleReply r;
	long fake_task = 0x12345678;

	printf("CHANGE_SIGNAL is accepted, and the task is kept\n");
	setup(&st, &io, "");

	r = console_dispatch(&st, ACTION_CHANGE_SIGNAL, 1, fake_task, NULL, 0);
	CHECK(r.res1 == DOSTRUE, "accepted, not refused as unknown");
	CHECK(st.unknown == 0, "not counted as unknown");
	CHECK(st.signal_task == (void *)fake_task, "dp_Arg2 recorded -- this is the ^C target");
	CHECK(st.signals_seen == 1, "counted");

	/* A zero task must not wipe a good one. */
	console_dispatch(&st, ACTION_CHANGE_SIGNAL, 1, 0, NULL, 0);
	CHECK(st.signal_task == (void *)fake_task, "a null task does not clear it");
}

/* ---- the ones that actually matter ------------------------------------- */

static void test_session_not_finished_while_handles_are_open(void)
{
	struct ConsoleState st;
	struct FakeIO io;

	printf("session is not finished while the shell holds handles\n");
	setup(&st, &io, "");

	/* The shell opens its own console first -- until it does, the session
	 * has not established and cannot be "finished" at all. */
	console_dispatch(&st, ACTION_FINDOUTPUT, 0, 0, NULL, 0);
	console_dispatch(&st, ACTION_END, 0, 0, NULL, 0);

	CHECK(!console_session_finished(&st), "two handles outstanding: not finished");

	console_dispatch(&st, ACTION_END, 1, 0, NULL, 0);
	CHECK(!console_session_finished(&st), "one handle outstanding: not finished");

	console_dispatch(&st, ACTION_END, 2, 0, NULL, 0);
	CHECK(console_session_finished(&st), "all closed: finished");
}

static void test_opens_are_counted_so_we_do_not_finish_early(void)
{
	struct ConsoleState st;
	struct FakeIO io;

	printf("a console opened mid-session delays completion\n");
	setup(&st, &io, "");

	/* The Shell opens "*" -- e.g. a program asking for the console. */
	console_dispatch(&st, ACTION_FINDINPUT, 0, 0, NULL, 0);
	CHECK(st.open_handles == 3, "three handles now outstanding");

	console_dispatch(&st, ACTION_END, 0, 0, NULL, 0);
	console_dispatch(&st, ACTION_END, 0, 0, NULL, 0);
	CHECK(!console_session_finished(&st),
	      "still one open: must not declare the session over");

	console_dispatch(&st, ACTION_END, 0, 0, NULL, 0);
	CHECK(console_session_finished(&st), "now it is over");
}

static void test_unbalanced_close_poisons_the_accounting(void)
{
	struct ConsoleState st;
	struct FakeIO io;

	printf("more closes than opens is treated as loss of tracking\n");
	setup(&st, &io, "");

	console_dispatch(&st, ACTION_END, 0, 0, NULL, 0);
	console_dispatch(&st, ACTION_END, 0, 0, NULL, 0);
	console_dispatch(&st, ACTION_END, 0, 0, NULL, 0);	/* one too many */

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
	console_dispatch(&st, ACTION_FINDOUTPUT, 0, 0, NULL, 0);
	console_dispatch(&st, ACTION_END, 0, 0, NULL, 0);

	CHECK(!console_safe_to_free_port(&st), "not at the start");

	console_dispatch(&st, ACTION_END, 0, 0, NULL, 0);
	console_dispatch(&st, ACTION_END, 0, 0, NULL, 0);
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

	r = console_dispatch(&st, ACTION_READ, 1, 0, buf, (long)sizeof(buf));
	CHECK(r.res1 == 0, "read reports EOF even though input remains");

	r = console_dispatch(&st, ACTION_WAIT_CHAR, 1000000, 0, NULL, 0);
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
		console_dispatch(&st, ACTION_WAIT_CHAR, 0, 0, buf, 0);

	CHECK(st.draining == 1, "draining after exceeding the cap");
}

/* ---- window size: the NAWS delivery path ------------------------------- */

/* ixemul sends CSI SP q and sscanf's back "1;1;%d;%d r". Source:
 * ixemul.library/library/__tioctl.c:280-312. */
static const char CSI_SP_Q[3] = { (char)0x9B, ' ', 'q' };

static long drain_reply(struct ConsoleState *st, char *out, long max)
{
	struct ConsoleReply r = console_dispatch(st, ACTION_READ, 1, 0, out, max);
	return r.res1;
}

static void test_size_report_exact_bytes(void)
{
	struct ConsoleState st;
	struct FakeIO io;
	char got[64];
	long n;

	printf("CSI SP q is answered with the exact bytes ixemul parses\n");
	setup(&st, &io, "");
	console_set_window_size(&st, 40, 120);	/* rows, cols */

	console_dispatch(&st, ACTION_WRITE, 2, 0, (void *)CSI_SP_Q, 3);
	CHECK(st.size_requests == 1, "the request was recognised");
	CHECK(io.out_len == 0, "and swallowed -- it must not reach the network");

	memset(got, 0, sizeof(got));
	n = drain_reply(&st, got, (long)sizeof(got));

	CHECK(n == 13, "reply length");
	CHECK((unsigned char)got[0] == 0x9B, "single-byte CSI, not ESC-[");
	CHECK(memcmp(got + 1, "1;1;40;120 r", 12) == 0,
	      "1;1; prefix, ROWS then COLS, space before r");
}

static void test_size_report_is_split_safe(void)
{
	struct ConsoleState st;
	struct FakeIO io;
	char got[64];

	printf("the request is recognised when split across three writes\n");
	setup(&st, &io, "");
	console_set_window_size(&st, 24, 80);

	console_dispatch(&st, ACTION_WRITE, 2, 0, (void *)&CSI_SP_Q[0], 1);
	console_dispatch(&st, ACTION_WRITE, 2, 0, (void *)&CSI_SP_Q[1], 1);
	console_dispatch(&st, ACTION_WRITE, 2, 0, (void *)&CSI_SP_Q[2], 1);

	CHECK(st.size_requests == 1, "recognised across write boundaries");
	CHECK(io.out_len == 0, "nothing leaked to the network");

	memset(got, 0, sizeof(got));
	drain_reply(&st, got, (long)sizeof(got));
	CHECK(memcmp(got + 1, "1;1;24;80 r", 11) == 0, "answered correctly");
}

static void test_partial_match_is_not_swallowed(void)
{
	struct ConsoleState st;
	struct FakeIO io;
	const unsigned char text[] = { 0x9B, ' ', 'H', 'i' };

	printf("a CSI that is not a size request still reaches the network\n");
	setup(&st, &io, "");

	console_dispatch(&st, ACTION_WRITE, 2, 0, (void *)text, 4);
	CHECK(st.size_requests == 0, "not treated as a request");
	CHECK(io.out_len == 4, "all four bytes forwarded");
	CHECK((unsigned char)io.out[0] == 0x9B && io.out[1] == ' '
	      && io.out[2] == 'H' && io.out[3] == 'i', "in the right order");
}

static void test_size_answered_from_current_value(void)
{
	struct ConsoleState st;
	struct FakeIO io;
	char got[64];

	printf("the answer uses the size at ASK time, not at connect time\n");
	setup(&st, &io, "");
	console_set_window_size(&st, 24, 80);
	console_set_window_size(&st, 50, 200);	/* NAWS resend after a resize */

	console_dispatch(&st, ACTION_WRITE, 2, 0, (void *)CSI_SP_Q, 3);
	memset(got, 0, sizeof(got));
	drain_reply(&st, got, (long)sizeof(got));

	CHECK(memcmp(got + 1, "1;1;50;200 r", 12) == 0, "the newer size wins");
}

static void test_unknown_size_reports_nothing(void)
{
	struct ConsoleState st;
	struct FakeIO io;
	char got[64];

	printf("with no NAWS yet, we stay silent rather than invent a size\n");
	setup(&st, &io, "");

	console_dispatch(&st, ACTION_WRITE, 2, 0, (void *)CSI_SP_Q, 3);
	CHECK(st.size_requests == 1, "request still counted");
	CHECK(drain_reply(&st, got, (long)sizeof(got)) == 0, "nothing queued");
}

static void test_size_reply_outranks_normal_input(void)
{
	struct ConsoleState st;
	struct FakeIO io;
	char got[64];
	long n;

	printf("a queued reply is delivered before ordinary typed input\n");
	setup(&st, &io, "hello\n");
	console_set_window_size(&st, 25, 80);

	console_dispatch(&st, ACTION_WRITE, 2, 0, (void *)CSI_SP_Q, 3);

	memset(got, 0, sizeof(got));
	n = drain_reply(&st, got, (long)sizeof(got));
	CHECK((unsigned char)got[0] == 0x9B, "reply comes first");

	memset(got, 0, sizeof(got));
	n = drain_reply(&st, got, (long)sizeof(got));
	CHECK(n == 6 && memcmp(got, "hello\n", 6) == 0,
	      "then the real input, undisturbed");
}

/* ---- deferred reads: the difference between idling and hanging up ------- */

static void test_empty_socket_defers_rather_than_signalling_eof(void)
{
	struct ConsoleState st;
	struct FakeIO io;
	char buf[64];
	struct ConsoleReply r;

	printf("no data yet defers the read; it must NOT look like EOF\n");
	setup(&st, &io, "");
	io.eof = 0;	/* a live socket with nothing to say right now */

	r = console_dispatch(&st, ACTION_READ, 1, 0, buf, (long)sizeof(buf));
	CHECK(r.defer == 1, "the packet is held, not answered");
	CHECK(r.res1 == 0, "and carries no byte count");
}

static void test_closed_socket_really_is_eof(void)
{
	struct ConsoleState st;
	struct FakeIO io;
	char buf[64];
	struct ConsoleReply r;

	printf("a closed peer IS end of file, so the shell can exit\n");
	setup(&st, &io, "");
	io.eof = 1;

	r = console_dispatch(&st, ACTION_READ, 1, 0, buf, (long)sizeof(buf));
	CHECK(r.defer == 0, "answered immediately");
	CHECK(r.res1 == 0, "with EOF");
}

static void test_deferred_read_succeeds_when_data_arrives(void)
{
	struct ConsoleState st;
	struct FakeIO io;
	char buf[64];
	struct ConsoleReply r;

	printf("re-dispatching a deferred read once bytes arrive works\n");
	setup(&st, &io, "");
	io.eof = 0;

	r = console_dispatch(&st, ACTION_READ, 1, 0, buf, (long)sizeof(buf));
	CHECK(r.defer == 1, "deferred while the socket is quiet");

	/* bytes turn up */
	io.in = "ls\n"; io.in_len = 3; io.in_pos = 0;

	memset(buf, 0, sizeof(buf));
	r = console_dispatch(&st, ACTION_READ, 1, 0, buf, (long)sizeof(buf));
	CHECK(r.defer == 0, "now answered");
	CHECK(r.res1 == 3 && memcmp(buf, "ls\n", 3) == 0, "with the real input");
}

static void test_draining_beats_deferral(void)
{
	struct ConsoleState st;
	struct FakeIO io;
	char buf[64];
	struct ConsoleReply r;

	printf("while draining we answer EOF rather than hold the packet\n");
	setup(&st, &io, "");
	io.eof = 0;
	console_begin_drain(&st);

	r = console_dispatch(&st, ACTION_READ, 1, 0, buf, (long)sizeof(buf));
	CHECK(r.defer == 0, "not deferred -- a held packet would never come back");
	CHECK(r.res1 == 0, "EOF, so the Shell leaves");
}

static void test_queued_size_report_is_never_deferred(void)
{
	struct ConsoleState st;
	struct FakeIO io;
	char buf[64];
	struct ConsoleReply r;
	static const char q[3] = { (char)0x9B, ' ', 'q' };

	printf("a queued size report answers even on a silent socket\n");
	setup(&st, &io, "");
	io.eof = 0;
	console_set_window_size(&st, 24, 80);

	console_dispatch(&st, ACTION_WRITE, 2, 0, (void *)q, 3);

	r = console_dispatch(&st, ACTION_READ, 1, 0, buf, (long)sizeof(buf));
	CHECK(r.defer == 0, "not deferred -- the asker is blocked on this");
	CHECK(r.res1 > 0, "the report is delivered");
}

static void test_launcher_handles_closing_is_not_session_end(void)
{
	struct ConsoleState st;
	struct FakeIO io;

	printf("the launcher returning its handles is NOT the session ending\n");
	setup(&st, &io, "");

	/* "NewShell <window>" returns as soon as it has launched the shell, so
	 * the two handles we gave it come straight back -- while the real Shell
	 * is only just starting. */
	console_dispatch(&st, ACTION_END, 1, 0, NULL, 0);
	console_dispatch(&st, ACTION_END, 2, 0, NULL, 0);

	CHECK(st.open_handles <= 0, "handle count really is zero");
	CHECK(!console_session_finished(&st),
	      "but the session is NOT over -- this tore down live sessions");
}

static void test_session_ends_once_established_and_released(void)
{
	struct ConsoleState st;
	struct FakeIO io;

	printf("a session ends when the shell's OWN console is released\n");
	setup(&st, &io, "");

	console_dispatch(&st, ACTION_FINDOUTPUT, 0, 0, NULL, 0);   /* shell opens its own */
	CHECK(st.established == 1, "established by the shell's own open");

	console_dispatch(&st, ACTION_END, 1, 0, NULL, 0);          /* launcher's two */
	console_dispatch(&st, ACTION_END, 2, 0, NULL, 0);
	CHECK(!console_session_finished(&st), "shell still holds one");

	console_dispatch(&st, ACTION_END, 0, 0, NULL, 0);          /* and the shell's */
	CHECK(console_session_finished(&st), "now it is over");
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
	test_change_signal_is_accepted_and_recorded();
	test_session_not_finished_while_handles_are_open();
	test_opens_are_counted_so_we_do_not_finish_early();
	test_unbalanced_close_poisons_the_accounting();
	test_port_is_never_declared_safe_to_free();
	test_draining_makes_the_shell_exit();
	test_packet_cap_triggers_drain();
	test_size_report_exact_bytes();
	test_size_report_is_split_safe();
	test_partial_match_is_not_swallowed();
	test_size_answered_from_current_value();
	test_unknown_size_reports_nothing();
	test_size_reply_outranks_normal_input();
	test_empty_socket_defers_rather_than_signalling_eof();
	test_closed_socket_really_is_eof();
	test_deferred_read_succeeds_when_data_arrives();
	test_draining_beats_deferral();
	test_queued_size_report_is_never_deferred();
	test_launcher_handles_closing_is_not_session_end();
	test_session_ends_once_established_and_released();

	printf("\n%d checks, %d failures\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
