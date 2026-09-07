/*
 * pwdump -- what does usergroup.library's user database actually contain?
 *
 * telnetd's authentication reported "no such user" for an account that exists
 * in MorphOS Preferences -> Users. Either getpwnam() reads a different store
 * than the prefs panel writes, or the database is empty, or the name differs.
 * Guessing between those is exactly what measurement is for.
 *
 * DELIBERATELY DOES NOT PRINT PASSWORD HASHES. A hash is not a password, but it
 * is still a credential, and this output goes into a log, a queue and a
 * transcript. Length and emptiness answer the question; the value itself does
 * not need to leave the machine.
 */

#include <exec/types.h>
#include <dos/dos.h>
#include <proto/exec.h>
#include <proto/dos.h>
#include <proto/usergroup.h>
#include <pwd.h>

#include <string.h>

struct Library *UserGroupBase = NULL;

static void say(CONST_STRPTR s)
{
	BPTR o = Output();
	if (o) Write(o, (APTR)s, (LONG)strlen((const char *)s));
}

static void say_num(CONST_STRPTR prefix, LONG v)
{
	char b[32]; char *p = b + sizeof(b); ULONG u;
	BOOL neg = FALSE;
	if (v < 0) { neg = TRUE; u = (ULONG)(-v); } else u = (ULONG)v;
	*--p = '\n';
	if (!u) *--p = '0';
	else while (u && p > b) { *--p = (char)('0' + (u % 10)); u /= 10; }
	if (neg && p > b) *--p = '-';
	say(prefix);
	Write(Output(), p, (LONG)(b + sizeof(b) - p));
}

static void show(struct passwd *pw)
{
	say("  name   : "); say(pw->pw_name ? (CONST_STRPTR)pw->pw_name : (CONST_STRPTR)"(null)"); say("\n");
	say("  gecos  : "); say(pw->pw_gecos ? (CONST_STRPTR)pw->pw_gecos : (CONST_STRPTR)"(null)"); say("\n");
	say("  home   : "); say(pw->pw_dir ? (CONST_STRPTR)pw->pw_dir : (CONST_STRPTR)"(null)"); say("\n");
	say("  shell  : "); say(pw->pw_shell ? (CONST_STRPTR)pw->pw_shell : (CONST_STRPTR)"(null)"); say("\n");
	say_num("  uid    : ", (LONG)pw->pw_uid);

	/* Emptiness and length only -- never the hash itself. */
	if (pw->pw_passwd == NULL)
		say("  passwd : NULL  -> would be REFUSED\n");
	else if (pw->pw_passwd[0] == '\0')
		say("  passwd : empty -> would be REFUSED (no password set)\n");
	else
		say_num("  passwd : set, hash length = ", (LONG)strlen(pw->pw_passwd));
	say("\n");
}

int main(int argc, char **argv)
{
	struct passwd *pw;
	int n = 0;

	UserGroupBase = OpenLibrary("usergroup.library", 0);
	if (UserGroupBase == NULL)
	{
		say("pwdump: cannot open usergroup.library\n");
		return RETURN_FAIL;
	}
	say("pwdump: usergroup.library opened\n\n");

	/* Who does the library think we are already? */
	{
		STRPTR who = getlogin();
		say("getlogin() -> ");
		say(who ? (CONST_STRPTR)who : (CONST_STRPTR)"(null)");
		say("\n");
		say_num("getuid()  -> ", (LONG)getuid());
		say("\n");
	}

	say("--- enumerating the password database ---\n");
	setpwent();
	while ((pw = getpwent()) != NULL)
	{
		n++;
		show(pw);
		if (n > 50) { say("  (stopping at 50)\n"); break; }
	}
	endpwent();
	say_num("entries found: ", (LONG)n);

	/* And the specific lookup telnetd does. */
	if (argc > 1 && argv[1] && argv[1][0])
	{
		say("\n--- getpwnam(\"");
		say((CONST_STRPTR)argv[1]);
		say("\") ---\n");
		pw = getpwnam((STRPTR)argv[1]);
		if (pw == NULL)
			say("  NULL -- no such user according to usergroup.library\n");
		else
			show(pw);
	}

	CloseLibrary(UserGroupBase);
	return RETURN_OK;
}
