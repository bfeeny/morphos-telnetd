#include "auth.h"

#include <stddef.h>

static int str_eq(const char *a, const char *b)
{
	if (a == NULL || b == NULL)
		return 0;
	while (*a && *b)
	{
		if (*a != *b)
			return 0;
		a++; b++;
	}
	return *a == *b;
}

enum AuthResult auth_policy(const char *stored, const char *typed_hash)
{
	if (stored == NULL)
		return AUTH_NO_SUCH_USER;

	/* Empty means no password configured. Fail closed. */
	if (stored[0] == '\0')
		return AUTH_NO_PASSWORD_SET;

	/*
	 * '*' is the Unix convention for an explicitly LOCKED account -- it is
	 * not a hash and no input can ever crypt() to it. Refusing it outright
	 * says so plainly rather than relying on the comparison to fail, and it
	 * distinguishes "locked" from "wrong password" in the log.
	 * The adjacent convention to an empty field, and both must refuse.
	 */
	if (stored[0] == '*' && stored[1] == '\0')
		return AUTH_LOCKED;

	if (typed_hash == NULL)
		return AUTH_BAD_CREDENTIALS;

	return str_eq(stored, typed_hash) ? AUTH_OK : AUTH_BAD_CREDENTIALS;
}

const char *auth_result_name(enum AuthResult r)
{
	switch (r)
	{
	case AUTH_OK:               return "ok";
	case AUTH_NO_SUCH_USER:     return "no such user";
	case AUTH_NO_PASSWORD_SET:  return "no password set for that account";
	case AUTH_LOCKED:           return "account is locked (*)";
	case AUTH_BAD_CREDENTIALS:  return "bad credentials";
	}
	return "unknown";
}
