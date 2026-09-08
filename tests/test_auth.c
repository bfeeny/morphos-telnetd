/*
 * Host tests for the authentication policy.
 *
 * getpwnam() and crypt() cannot run here; the DECISION they feed can, and the
 * decision is the part that must not be wrong. Testing "this must be refused"
 * by asserting a verdict rather than by attempting a login is the same rule
 * this fleet adopted after nearly formatting a disk to prove a guard worked.
 */

#include "../src/auth.h"

#include <stdio.h>

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

int main(void)
{
	printf("authentication policy -- host tests\n\n");

	printf("a matching hash is accepted\n");
	CHECK(auth_policy("$1$abc$hashed", "$1$abc$hashed") == AUTH_OK,
	      "identical hashes authenticate");

	printf("a wrong hash is refused\n");
	CHECK(auth_policy("$1$abc$hashed", "$1$abc$OTHER") == AUTH_BAD_CREDENTIALS,
	      "different hashes do not");

	printf("AN ACCOUNT WITH NO PASSWORD IS REFUSED, NOT ADMITTED\n");
	CHECK(auth_policy("", "anything") == AUTH_NO_PASSWORD_SET,
	      "empty pw_passwd refuses");
	CHECK(auth_policy("", "") == AUTH_NO_PASSWORD_SET,
	      "and an empty attempt does not sneak past it");

	printf("an EXPLICITLY LOCKED account (*) is refused\n");
	CHECK(auth_policy("*", "anything") == AUTH_LOCKED,
	      "'*' is a lock, not a hash -- refuse it by name");
	CHECK(auth_policy("*", "*") == AUTH_LOCKED,
	      "and it cannot be matched by supplying '*' either");

	printf("a hash that merely STARTS with * is still a hash\n");
	CHECK(auth_policy("*abc", "*abc") == AUTH_OK,
	      "only a bare '*' means locked");

	printf("an unknown user is refused\n");
	CHECK(auth_policy(0, "anything") == AUTH_NO_SUCH_USER, "NULL stored entry");

	printf("a null attempt never authenticates\n");
	CHECK(auth_policy("$1$abc$hashed", 0) == AUTH_BAD_CREDENTIALS,
	      "NULL typed hash");

	printf("a prefix of the stored hash is not a match\n");
	CHECK(auth_policy("$1$abc$hashed", "$1$abc$hash") == AUTH_BAD_CREDENTIALS,
	      "no partial comparison");

	printf("\n%d checks, %d failures\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
