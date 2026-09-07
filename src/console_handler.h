/*
 * console_handler -- the shell-attach layer, as a pure decision function.
 *
 * This is the reusable half of the project: the thing that makes a spawned
 * MorphOS Shell believe it is talking to a console. A telnetd is one consumer;
 * an sshd is the intended second. Nothing in here knows about sockets, telnet,
 * or ssh.
 *
 * It is deliberately free of MorphOS system calls. Everything the outside
 * world provides -- bytes in, bytes out -- arrives through callbacks, so the
 * whole packet protocol can be exercised on the build host with no hardware
 * and no risk. That is not a stylistic preference: on a machine with no memory
 * protection, mishandling one packet takes down the OS, so this logic must be
 * testable somewhere that a mistake is free.
 *
 * Packet semantics and constant values: MorphOS SDK 3.20 (sdk-20260529),
 * Development/gg/os-include/dos/dosextens.h and Autodoc/dos.doc.
 */

#ifndef CONSOLE_HANDLER_H
#define CONSOLE_HANDLER_H

#include <stddef.h>

/*
 * On MorphOS we take these from the SDK. On the build host -- where the tests
 * run -- we define them ourselves, with the same values, so the tests exercise
 * the real dispatch rather than a mock of it.
 */
#ifdef __MORPHOS__
#  include <dos/dos.h>
#  include <dos/dosextens.h>
#else
#  define ACTION_READ              'R'
#  define ACTION_WRITE             'W'
#  define ACTION_WAIT_CHAR          20
#  define ACTION_DISK_INFO          25
#  define ACTION_SCREEN_MODE       994
#  define ACTION_CHANGE_SIGNAL     995
#  define ACTION_FINDUPDATE       1004
#  define ACTION_FINDINPUT        1005
#  define ACTION_FINDOUTPUT       1006
#  define ACTION_END              1007
#  define ACTION_SEEK             1008
#  define ACTION_IS_FILESYSTEM    1027
#  define DOSTRUE                   -1L
#  define DOSFALSE                   0L
#  define ERROR_ACTION_NOT_KNOWN    209L
#endif

/* Result of dispatching one packet: what to put in dp_Res1 / dp_Res2. */
struct ConsoleReply
{
	long res1;
	long res2;
};

struct ConsoleState;

/*
 * Supply bytes to the Shell. Return the number placed in buf (0 == EOF).
 * In the probe this reads a canned script; in telnetd it reads the socket.
 * Must never write more than len bytes.
 */
typedef long (*console_read_fn)(void *ctx, void *buf, long len);

/*
 * Consume bytes the Shell produced. Return the number accepted.
 * In the probe this is stdout; in telnetd it is the socket.
 */
typedef long (*console_write_fn)(void *ctx, const void *buf, long len);

struct ConsoleState
{
	console_read_fn   read_fn;
	console_write_fn  write_fn;
	void             *io_ctx;

	long open_handles;	/* handles the Shell currently holds from us */
	long opens_seen;	/* cumulative opens: initial handles + FIND requests */
	long ends_seen;	/* cumulative ACTION_END */
	long packets;	/* everything dispatched, for the cap */
	long unknown;	/* packets we did not recognise */

	/*
	 * ACTION_CHANGE_SIGNAL hands us the task that wants to be signalled --
	 * on a real console this is how ^C reaches the running program. We spawn
	 * the Shell through SystemTagList() and never get a Process pointer back,
	 * so this packet is the only route to the identity we need in order to
	 * turn telnet's Interrupt Process into SIGBREAKF_CTRL_C.
	 */
	void *signal_task;
	long  signals_seen;

	int  raw_mode;	/* last ACTION_SCREEN_MODE: 1 raw, 0 cooked */
	int  draining;	/* wind down: reads return EOF so the Shell exits */
	int  inconsistent;	/* accounting went wrong -- never tear down */

	long max_packets;	/* 0 == unlimited */
};

/* Initialise. `initial_handles` is how many we handed the Shell up front
 * (SYS_Input + SYS_Output == 2), which it will close on exit. */
void console_init(struct ConsoleState *st,
                  console_read_fn read_fn,
                  console_write_fn write_fn,
                  void *io_ctx,
                  long initial_handles,
                  long max_packets);

/*
 * Dispatch one packet. `type` is dp_Type; arg1..arg3 are dp_Arg1..dp_Arg3.
 * For ACTION_READ, arg2 is the destination buffer; for ACTION_WRITE, the
 * source. The caller supplies them as pointers so this stays free of BPTR
 * arithmetic and stays testable.
 */
struct ConsoleReply console_dispatch(struct ConsoleState *st,
                                     long type,
                                     long arg1,
                                     void *bufarg,
                                     long len);

/* Ask for a wind-down: subsequent reads report EOF, so the Shell exits of
 * its own accord rather than having its handles pulled out from under it. */
void console_begin_drain(struct ConsoleState *st);

/*
 * Is the session finished -- may the caller stop servicing packets?
 * True only when every handle we granted has been closed and the accounting
 * stayed consistent throughout.
 */
int console_session_finished(const struct ConsoleState *st);

/*
 * May the caller free the message port?
 *
 * Separate from console_session_finished() on purpose, and it currently always
 * answers NO. Freeing a port a Shell might still hold a handle to is the one
 * mistake here that takes the whole OS down rather than failing politely, and
 * the only thing that would stand between a bug in this file and that outcome
 * is this file. So the answer does not depend on this file being correct.
 *
 * A leaked MsgPort costs a few hundred bytes until the next reboot. That is
 * the right side of the trade by a wide margin.
 */
int console_safe_to_free_port(const struct ConsoleState *st);

#endif /* CONSOLE_HANDLER_H */
