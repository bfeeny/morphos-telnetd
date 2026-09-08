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
/*
 * ACTION_SESSION_MODE is IXEMUL'S OWN PACKET, not AmigaDOS's. It is defined in
 * ixemul.library/library/_cli_parse.c:60 and appears in no SDK header, which is
 * why it arrives as an unidentifiable 991 and only ever from ixemul binaries.
 * Identified by morphos-oracle from the ixemul source.
 */
#define ACTION_SESSION_MODE 991

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

	/*
	 * When set, DO NOT REPLY TO THIS PACKET YET.
	 *
	 * A console read blocks until a key arrives. With a socket underneath,
	 * "nothing to read right now" is the normal case, and it is NOT
	 * end-of-file -- but replying 0 is exactly how a handler says EOF, and
	 * the Shell would exit. So the packet is held and answered when bytes
	 * turn up. This is the one thing a socket needs that a canned buffer
	 * never did.
	 */
	int defer;
};

struct ConsoleState;

/*
 * Supply bytes to the Shell. Must never write more than len bytes.
 *
 *   > 0  that many bytes were placed in buf
 *   = 0  nothing available RIGHT NOW -- the read will be deferred, not
 *        answered. A non-blocking socket with no data returns this.
 *   < 0  end of file: the peer is gone. The Shell is allowed to exit.
 *
 * The 0/-1 distinction is the whole difference between a session that idles
 * at a prompt and one that hangs up the moment you stop typing.
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
	 * ACTION_CHANGE_SIGNAL -- how ^C reaches the program in the session.
	 *
	 * Documented in dos.library/AAA-Packet-Documentation, which is NOT in
	 * the MorphOS SDK (it is on wiki.amigaos.net; mirrored locally under
	 * Documentation/dos-packets/). Verbatim:
	 *
	 *   "This packet redirects what process the console handler signals
	 *    when the user hits Control-C, Control-D, Control-E, or Control-F."
	 *
	 *   dp_Arg1 - filehandle->fh_Arg1 of the console file handle
	 *   dp_Arg2 - (struct MsgPort *) MsgPort of the process to signal
	 *   dp_Arg3 - (struct FileHandle *) added 53.49, previously 0
	 *
	 * dp_Arg2 IS A MsgPort, NOT A TASK. Measurement alone could not tell
	 * them apart -- both are Exec structures from the same pools, so the
	 * pointer looked task-shaped and was recorded here as a task. To signal
	 * it, take port->mp_SigTask; signalling the port itself would not work.
	 *
	 * The measurements now all have explanations: dp_Arg1 was constant at 1
	 * because it is OUR OWN fh_Arg1 coming back to us, and dp_Arg3 was
	 * always 0 because MorphOS does not implement the 53.49 extension.
	 */
	void *signal_port;	/* struct MsgPort * -- signal port->mp_SigTask */
	long  signals_seen;

	long  session_mode_asks;	/* ACTION_SESSION_MODE, ixemul startup */

	/*
	 * Window size, and the machinery for reporting it.
	 *
	 * MorphOS has NO resize notification -- there is no packet for it among
	 * the 82 ACTION_* constants. So a program cannot be told the size has
	 * changed; it can only ask, and we must answer from whatever NAWS last
	 * told us AT THE MOMENT IT ASKS. Never from a value cached at connect.
	 *
	 * The Amiga-native query is CSI SP q (9B 20 71) -- CSI is the single
	 * byte 0x9B, not ESC-[. ixemul's TIOCGWINSZ sends exactly that and
	 * parses back "1;1;<rows>;<cols> r" (note the space before 'r').
	 * Source: ixemul.library/library/__tioctl.c:280-312.
	 *
	 * The program writes that request to its console -- i.e. to us -- so we
	 * detect it in the outgoing stream, swallow it, and queue the answer
	 * where the next read will find it.
	 */
	long rows, cols;	/* 0 == unknown, report nothing */

	unsigned char pending[48];	/* queued reply awaiting an ACTION_READ */
	long          pending_len;
	long          pending_pos;

	int  q_state;	/* incremental match of CSI SP q across writes */
	long size_requests;

	/*
	 * Has the Shell opened a console of its own yet?
	 *
	 * The two handles handed to SystemTagList() are closed by the caller as
	 * soon as the COMMAND returns -- and "NewShell <window>" returns once it
	 * has LAUNCHED the shell, not when that shell exits. So the initial
	 * handles go away almost immediately while the session is just starting.
	 *
	 * Treating a zero handle count as "session over" therefore tore down
	 * live sessions about two seconds in, and only when the Shell had not
	 * yet got around to opening its own handles -- a race, which is why it
	 * sometimes appeared to work.
	 */
	int  established;

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
                                     long arg2,
                                     void *bufarg,
                                     long len);

/* Ask for a wind-down: subsequent reads report EOF, so the Shell exits of
 * its own accord rather than having its handles pulled out from under it. */
void console_begin_drain(struct ConsoleState *st);

/*
 * Tell the handler the terminal's current size, as NAWS reports it.
 * Safe to call at any time and as often as the client resends.
 */
void console_set_window_size(struct ConsoleState *st, long rows, long cols);

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
