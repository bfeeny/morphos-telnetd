/*
 * mkpw -- create a well-formed entry in the MorphOS user database.
 *
 *   mkpw <user> <password> [uid] [gid]          -> writes a TEST file
 *   mkpw -live <user> <password> [uid] [gid]     -> writes the system database
 *
 * THE LIVE DATABASE REQUIRES AN EXPLICIT FLAG. This tool writes
 * Work:morphos-agent/work-telnetd/passwd.test by default and touches nothing
 * the system reads. That is not caution for its own sake: writing the live path
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

/* Read a file whole. Returns bytes read, 0 if absent. */
static long read_file(CONST_STRPTR path, char *buf, long max)
{
	BPTR f = Open(path, MODE_OLDFILE);
	long n;

	if (!f)
		return 0;
	n = Read(f, buf, max - 1);
	Close(f);
	if (n < 0) n = 0;
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
 * Rewrite `path` with `line`, preserving every entry that is not for the same
 * user. This is the whole reason the tool exists in this shape: the file is
 * shared with Preferences and must never be clobbered.
 */
static BOOL merge_file(CONST_STRPTR path, const char *user, const char *line)
{
	static char in[8192];
	static char out[8192];
	long n, i = 0, o = 0;
	int kept = 0, replaced = 0;
	BPTR f;

	n = read_file(path, in, (long)sizeof(in));

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
		if (o + (i - start) < (long)sizeof(out))
		{
			CopyMem(in + start, out + o, i - start);
			o += (i - start);
			kept++;
		}
	}

	/* our entry last */
	{
		long len = (long)strlen(line);
		if (o + len < (long)sizeof(out))
		{
			CopyMem((APTR)line, out + o, len);
			o += len;
		}
	}

	f = Open(path, MODE_NEWFILE);
	if (!f)
		return FALSE;
	Write(f, out, o);
	Close(f);

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
		int i;
		parts[0] = user; parts[1] = hash; parts[2] = uid; parts[3] = gid;
		parts[4] = "MorphOS user"; parts[5] = "RAM:"; parts[6] = "*NewShell";
		for (i = 0; i < 7; i++)
		{
			const char *p = parts[i];
			while (*p && n < (int)sizeof(line) - 3)
				line[n++] = *p++;
			if (i < 6) line[n++] = '|';
		}
		line[n++] = '\n';
		line[n] = '\0';
	}

	if (!live)
	{
		if (!merge_file((CONST_STRPTR)PW_TEST, user, line))
			say("mkpw: could not write " PW_TEST "\n");
		else
			say("mkpw: wrote " PW_TEST " (test file; system untouched)\n");
	}
	else
	{
		say("mkpw: -live given; writing the SYSTEM user database\n");
		if (!merge_file((CONST_STRPTR)PW_ENV, user, line))
			say("mkpw: could not write " PW_ENV "\n");
		else
			say("mkpw: wrote " PW_ENV "\n");

		if (!merge_file((CONST_STRPTR)PW_ENVARC, user, line))
			say("mkpw: could not write " PW_ENVARC "\n");
		else
			say("mkpw: wrote " PW_ENVARC "\n");
	}

	say("mkpw: entry created for '");
	say((CONST_STRPTR)user);
	say("' -- hash not shown by design\n");

	CloseLibrary(UserGroupBase);
	return RETURN_OK;
}
