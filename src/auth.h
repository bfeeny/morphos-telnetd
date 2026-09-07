/*
 * auth.h -- who is allowed in.
 *
 * The POLICY lives here as a pure function so it can be tested on the build
 * host: MorphOS's getpwnam()/crypt() cannot run there, but the decision they
 * feed can, and the decision is the part that must not be wrong.
 */

#ifndef AUTH_H
#define AUTH_H

enum AuthResult
{
	AUTH_OK = 0,
	AUTH_NO_SUCH_USER,	/* no entry for that name */
	AUTH_NO_PASSWORD_SET,	/* entry exists but has no password -- REFUSE */
	AUTH_BAD_CREDENTIALS	/* wrong password */
};

/*
 * Decide, given the stored field and the hash of what was typed.
 *
 * `stored` is struct passwd's pw_passwd, which holds a SALTED HASH, not a
 * password -- so this compares hashes and the daemon never holds a secret for
 * longer than it takes to crypt() one.
 *
 * An account with no password set is REFUSED, not admitted. That is a
 * deliberate policy choice (Brian, 2026-09-07) and the important one: the
 * out-of-the-box MorphOS state is a blank password, so failing open here would
 * mean a plaintext daemon handing a shell to anyone who connects. A user must
 * set a password in Preferences before remote login works.
 */
enum AuthResult auth_policy(const char *stored, const char *typed_hash);

/* For logs and for telling the user what went wrong -- never leaks which of
 * "no such user" and "wrong password" applied when talking to the client. */
const char *auth_result_name(enum AuthResult r);

#endif /* AUTH_H */
