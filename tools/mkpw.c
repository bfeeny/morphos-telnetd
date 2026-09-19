/*
 * mkpw -- create a well-formed entry in the MorphOS user database.
 *
 *   mkpw <user> <password> [uid] [gid]          -> writes a TEST file
 *   mkpw -live <user> <password> [uid] [gid]     -> writes the system database
 *
 * THE LIVE DATABASE REQUIRES AN EXPLICIT FLAG. Without -live this tool writes
 * passwd.test in the current directory and touches nothing the system reads. That is not caution for its own sake: writing the live path
 * on every test run destroyed the machine owner's account, and very possibly
 * the only copy of a credential we were trying to locate. A tool that mutates
 * shared state as its DEFAULT behaviour will eventually do it at the worst
 * moment. Make the dangerous thing require an act.
 *
 * MorphOS ships usergroup.library and netinfo.device but nothing that
 * POPULATES the passwd unit, so there is no supported way to create an account
 * getpwnam() can see. This is the smallest thing that fills that gap.
 *
 * TWO TRAPS IT EXISTS TO AVOID:
 *
 * 1. THE FORMAT IS PIPE-SEPARATED, not colon. AmiTCP chose '|' precisely
 *    because AmigaDOS volume names contain colons -- a home directory of
 *    "Ram Disk:" or a shell of "*NewShell" would wreck a colon format. Verified
 *    by reading back an entry written this way:
 *
 *      telnettest|<hash>|1000|100|Telnet Test|RAM:|*NewShell
 *
 *    so a colon in the home field is fine, and a PIPE is what must not appear.
 *
 * 2. The password field must be a real crypt hash. "*" is the Unix convention
 *    for a LOCKED account and can never authenticate.
 *
 * IT IS NON-DESTRUCTIVE. The passwd file holds accounts this tool did not
 * create -- MorphOS Preferences -> Users writes to the very same file, which is
 * now measured rather than assumed. An earlier version opened it MODE_NEWFILE
 * and truncated it, destroying the machine owner's account. Existing entries
 * are read, preserved, and written back; an entry with the same name is
 * replaced, everything else is left exactly as found.
 *
 * IT NEVER PRINTS THE HASH. The hash is written straight to the file. A hash is
 * not a password, but it is still a credential, and output from this machine
 * crosses a job queue and two transcripts before anyone reads it.
 */

#include <exec/types.h>
#include <dos/dos.h>
#include <proto/exec.h>
#include <proto/dos.h>
#include <proto/usergroup.h>

#include <string.h>

struct Library *UserGroupBase = NULL;

#define PW_ENV    "ENV:sys/net/passwd"
#define PW_ENVARC "ENVARC:sys/net/passwd"
#define PW_TEST   "passwd.test"

static void say(CONST_STRPTR s)
{
	BPTR o = Output();
	if (o) Write(o, (APTR)s, (LONG)strlen((const char *)s));
}

static int has_pipe(const char *s)
{
	while (*s) if (*s++ == '|') return 1;
	return 0;
}

/*
 * Read a file whole, and REFUSE rather than truncate.
 *
 * The old version asked for max-1 bytes and returned whatever it got, so a
 * passwd file larger than the buffer was silently cut -- mid-line, most likely
 * -- and everything past the cut was then written back out as though it had
 * never existed. Quietly losing accounts is the one thing this tool must not
 * do; it was written because that already happened once.
 *
 *   >= 0  bytes read
 *     -1  present, but too large to rewrite safely
 */
static long read_file(CONST_STRPTR path, char *buf, long max)
{
	BPTR f = Open(path, MODE_OLDFILE);
	long n;

	if (!f)
	{
		/*
		 * "Absent" and "there but unreadable" are NOT the same answer,
		 * and treating both as an empty file is how this tool would
		 * have destroyed the database it exists to protect: with n = 0
		 * the merge preserves nothing, and the new entry is installed
		 * as the WHOLE user database. Preferences holding the file open
		 * is enough to trigger it.
		 */
		if (IoErr() == ERROR_OBJECT_NOT_FOUND)
			return 0;
		return -1;
	}

	n = Read(f, buf, max);
	Close(f);

	if (n < 0)
		return -1;	/* a read error is not an empty file either */
	if (n >= max)
		return -1;	/* filled the buffer: there may well be more */

	buf[n] = '\0';
	return n;
}

static int name_matches(const char *line, const char *user)
{
	while (*user && *line && *line != '|')
	{
		if (*line != *user) return 0;
		line++; user++;
	}
	return (*user == '\0' && *line == '|');
}

/*
 * Replace a file's contents without ever leaving it shorter than it was.
 *
 * MODE_NEWFILE truncates the moment it opens, so the old code destroyed the
 * database BEFORE it knew whether the replacement could be written -- a full
 * disk, a failed Write, a crash between the two, and the accounts were gone.
 * The new contents therefore go to a file beside the target and are moved into
 * place, with the previous version kept as `.old`, which is the convention
 * Preferences already uses for this very file.
 */
static BOOL write_whole(CONST_STRPTR path, const char *data, long len)
{
	char tmp[256], bak[256];
	BPTR f;
	long i = 0;

	while (path[i] && i < (long)sizeof(tmp) - 5)
	{
		tmp[i] = (char)path[i];
		bak[i] = (char)path[i];
		i++;
	}
	if (path[i] != '\0')
		return FALSE;		/* too long to do this safely */

	CopyMem((APTR)".new", tmp + i, 5);
	CopyMem((APTR)".old", bak + i, 5);

	f = Open((CONST_STRPTR)tmp, MODE_NEWFILE);
	if (!f)
		return FALSE;
	if (Write(f, (APTR)data, len) != len)
	{
		Close(f);
		DeleteFile((CONST_STRPTR)tmp);
		return FALSE;
	}
	Close(f);

	DeleteFile((CONST_STRPTR)bak);		/* may not exist; that is fine */
	Rename(path, (CONST_STRPTR)bak);	/* may not exist; that is fine */

	if (!Rename((CONST_STRPTR)tmp, path))
	{
		Rename((CONST_STRPTR)bak, path);	/* put back what was there */
		DeleteFile((CONST_STRPTR)tmp);
		return FALSE;
	}

	return TRUE;
}

/*
 * Rewrite `path` with `line`, preserving every entry that is not for the same
 * user. This is the whole reason the tool exists in this shape: the file is
 * shared with Preferences and must never be clobbered.
 *
 * Every way of coming up short now REFUSES instead of writing what it managed.
 * A partial rewrite of a credential store is worse than no rewrite at all, and
 * the caller cannot tell the difference unless it is told.
 */
static BOOL merge_file(CONST_STRPTR path, const char *user, const char *line)
{
	static char in[8192];
	static char out[8192];
	long n, i = 0, o = 0;
	int replaced = 0;

	n = read_file(path, in, (long)sizeof(in));
	if (n < 0)
	{
		say("mkpw: cannot read the existing file -- it may be locked by\n");
		say("      Preferences, or larger than this tool can rewrite.\n");
		say("      Refusing: a merge that cannot see the old entries\n");
		say("      would replace them all with this one.\n");
		return FALSE;
	}

	while (i < n)
	{
		long start = i;
		while (i < n && in[i] != '\n') i++;
		if (i < n) i++;			/* include the newline */

		if (in[start] == '\n' || i == start)
			continue;		/* blank */

		if (name_matches(in + start, user))
		{
			replaced = 1;
			continue;		/* drop: the new line replaces it */
		}

		if (o + (i - start) >= (long)sizeof(out))
		{
			say("mkpw: no room to preserve every existing entry; refusing\n");
			return FALSE;
		}
		CopyMem(in + start, out + o, i - start);
		o += (i - start);
	}

	/*
	 * End the last preserved entry before starting ours.
	 *
	 * A passwd file whose final line has no trailing newline -- hand-edited,
	 * or written by something that did not bother -- used to have the last
	 * existing account and the new one run together into a single
	 * unparseable line. That is the same shape of damage as the truncation
	 * this tool was written to prevent, and it survived the rewrite that was
	 * supposed to fix it.
	 */
	if (o > 0 && out[o - 1] != '\n')
	{
		if (o + 1 >= (long)sizeof(out))
		{
			say("mkpw: no room to terminate the last entry; refusing\n");
			return FALSE;
		}
		out[o++] = '\n';
	}

	{
		long len = (long)strlen(line);
		if (o + len >= (long)sizeof(out))
		{
			say("mkpw: no room for the new entry; refusing\n");
			return FALSE;
		}
		CopyMem((APTR)line, out + o, len);
		o += len;
	}

	if (!write_whole(path, out, o))
		return FALSE;

	say(replaced ? "  (replaced an existing entry of the same name)\n"
	             : "  (added; existing entries preserved)\n");
	return TRUE;
}

int main(int argc, char **argv)
{
	char line[256];
	char salt[64];
	const char *user, *pass;
	const char *uid = "1000", *gid = "100";
	int live = 0;
	char *hash;
	int n = 0;

	{
		int a = 1;

		if (argc > 1 && argv[1][0] == '-' && argv[1][1] == 'l')
		{
			live = 1;
			a = 2;
		}
		if (argc < a + 2)
		{
			say("usage: mkpw [-live] <user> <password> [uid] [gid]\n");
			say("  without -live, writes " PW_TEST " and touches nothing else\n");
			return RETURN_ERROR;
		}
		user = argv[a];
		pass = argv[a + 1];
		if (argc > a + 2) uid = argv[a + 2];
		if (argc > a + 3) gid = argv[a + 3];
	}

	if (has_pipe(user) || has_pipe(uid) || has_pipe(gid))
	{
		say("mkpw: a pipe in any field would corrupt the entry; refusing\n");
		return RETURN_ERROR;
	}

	UserGroupBase = OpenLibrary("usergroup.library", 0);
	if (!UserGroupBase)
	{
		say("mkpw: cannot open usergroup.library\n");
		return RETURN_FAIL;
	}
	{
		/* Required before any database call. See telnetd.c. */
		struct TagItem tags[1];
		tags[0].ti_Tag = TAG_DONE; tags[0].ti_Data = 0;
		ug_SetupContextTagList((CONST_STRPTR)"mkpw", tags);
	}

	/*
	 * A salt of our own, because ug_GetSalt() needs an existing entry and
	 * that is the thing being created. Two characters is the classic form.
	 * Verification then uses ug_GetSalt() against the stored entry, which is
	 * the library's own answer for whatever format it holds.
	 */
	salt[0] = 'M'; salt[1] = 'O'; salt[2] = '\0';

	hash = (char *)crypt((STRPTR)pass, (STRPTR)salt);
	if (hash == NULL || hash[0] == '\0')
	{
		say("mkpw: crypt() produced nothing\n");
		CloseLibrary(UserGroupBase);
		return RETURN_FAIL;
	}

	/*
	 * name:hash:uid:gid:gecos:home:shell   -- exactly seven fields.
	 * Home is "/RAM": the same place as RAM: with no colon to break the
	 * parse. Shell is left empty deliberately; telnetd starts the Shell.
	 */
	{
		const char *parts[7];
		int i, fits = 1;

		parts[0] = user; parts[1] = hash; parts[2] = uid; parts[3] = gid;
		parts[4] = "MorphOS user"; parts[5] = "RAM:"; parts[6] = "*NewShell";

		for (i = 0; i < 7 && fits; i++)
		{
			const char *p = parts[i];

			while (*p)
			{
				if (n >= (int)sizeof(line) - 2) { fits = 0; break; }
				line[n++] = *p++;
			}
			if (fits && i < 6)
			{
				if (n >= (int)sizeof(line) - 2) fits = 0;
				else line[n++] = '|';
			}
		}

		/*
		 * The separator used to be appended with no bounds check at all,
		 * so a long enough username ran off the end of this buffer. And
		 * even where it fitted, a clipped entry is not a lesser entry: a
		 * clipped hash can never authenticate and a clipped name is a
		 * different account. Refuse it.
		 */
		if (!fits)
		{
			say("mkpw: the entry does not fit; refusing to write a truncated one\n");
			CloseLibrary(UserGroupBase);
			return RETURN_ERROR;
		}

		line[n++] = '\n';
		line[n] = '\0';
	}

	/*
	 * The exit status has to mean something.
	 *
	 * Every refusal above used to print its reason and then fall through to
	 * "entry created" and RETURN_OK -- so a passwd file too big to rewrite
	 * produced "refusing", then "entry created", then success, and any
	 * script reading the status believed the account existed. With -live the
	 * ENV and ENVARC copies could also disagree under the same rc.
	 */
	{
		int failures = 0;

		if (!live)
		{
			if (!merge_file((CONST_STRPTR)PW_TEST, user, line))
			{
				say("mkpw: could not write " PW_TEST "\n");
				failures++;
			}
			else
				say("mkpw: wrote " PW_TEST " (test file; system untouched)\n");
		}
		else
		{
			say("mkpw: -live given; writing the SYSTEM user database\n");

			if (!merge_file((CONST_STRPTR)PW_ENV, user, line))
			{
				say("mkpw: could not write " PW_ENV "\n");
				failures++;
			}
			else
				say("mkpw: wrote " PW_ENV "\n");

			if (!merge_file((CONST_STRPTR)PW_ENVARC, user, line))
			{
				say("mkpw: could not write " PW_ENVARC "\n");
				failures++;
			}
			else
				say("mkpw: wrote " PW_ENVARC "\n");
		}

		CloseLibrary(UserGroupBase);

		if (failures)
		{
			say("mkpw: NO entry was created -- see the reason above\n");
			return RETURN_ERROR;
		}

		say("mkpw: entry created for '");
		say((CONST_STRPTR)user);
		say("' -- hash not shown by design\n");
		return RETURN_OK;
	}
}
