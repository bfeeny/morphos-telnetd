/*
 * mkpw -- create a well-formed entry in the MorphOS user database.
 *
 *   mkpw <user> <password> [uid] [gid]
 *
 * MorphOS ships usergroup.library and netinfo.device but nothing that
 * POPULATES the passwd unit, so there is no supported way to create an account
 * getpwnam() can see. This is the smallest thing that fills that gap.
 *
 * TWO TRAPS IT EXISTS TO AVOID:
 *
 * 1. AmigaDOS volume names contain a colon, and colon is the passwd field
 *    separator. Writing "RAM:" as a home directory produces EIGHT fields
 *    instead of seven and the entry is silently unusable -- which looks exactly
 *    like an empty database from getpwnam's side. Home is written in POSIX form
 *    with no colon, and any colon in a supplied field is rejected outright.
 *
 * 2. The password field must be a real crypt hash. "*" is the Unix convention
 *    for a LOCKED account and can never authenticate.
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

static void say(CONST_STRPTR s)
{
	BPTR o = Output();
	if (o) Write(o, (APTR)s, (LONG)strlen((const char *)s));
}

static int has_colon(const char *s)
{
	while (*s) if (*s++ == ':') return 1;
	return 0;
}

static BOOL write_file(CONST_STRPTR path, const char *line)
{
	BPTR f = Open(path, MODE_NEWFILE);
	if (!f)
		return FALSE;
	Write(f, (APTR)line, (LONG)strlen(line));
	Close(f);
	return TRUE;
}

int main(int argc, char **argv)
{
	char line[256];
	char salt[64];
	const char *user, *pass;
	const char *uid = "1000", *gid = "100";
	char *hash;
	int n = 0;

	if (argc < 3)
	{
		say("usage: mkpw <user> <password> [uid] [gid]\n");
		return RETURN_ERROR;
	}
	user = argv[1];
	pass = argv[2];
	if (argc > 3) uid = argv[3];
	if (argc > 4) gid = argv[4];

	if (has_colon(user) || has_colon(uid) || has_colon(gid))
	{
		say("mkpw: a colon in any field would corrupt the entry; refusing\n");
		return RETURN_ERROR;
	}

	UserGroupBase = OpenLibrary("usergroup.library", 0);
	if (!UserGroupBase)
	{
		say("mkpw: cannot open usergroup.library\n");
		return RETURN_FAIL;
	}

	/* A salt of our own; ug_GetSalt needs an existing entry, which is the
	 * thing we are trying to create. Two characters is the classic form. */
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
		parts[4] = "MorphOS user"; parts[5] = "/RAM"; parts[6] = "";
		for (i = 0; i < 7; i++)
		{
			const char *p = parts[i];
			while (*p && n < (int)sizeof(line) - 3)
				line[n++] = *p++;
			if (i < 6) line[n++] = ':';
		}
		line[n++] = '\n';
		line[n] = '\0';
	}

	if (!write_file((CONST_STRPTR)PW_ENV, line))
		say("mkpw: could not write " PW_ENV "\n");
	else
		say("mkpw: wrote " PW_ENV "\n");

	if (!write_file((CONST_STRPTR)PW_ENVARC, line))
		say("mkpw: could not write " PW_ENVARC "\n");
	else
		say("mkpw: wrote " PW_ENVARC "\n");

	say("mkpw: entry created for '");
	say((CONST_STRPTR)user);
	say("' -- hash not shown by design\n");

	CloseLibrary(UserGroupBase);
	return RETURN_OK;
}
