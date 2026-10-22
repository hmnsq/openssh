/*
 * Copyright (c) 2004, 2005 Darren Tucker.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ SSH_AUDIT_EVENTS

#ਅਨ੍ਤਰ੍ਭਾਵ "audit.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "hostfile.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "auth.h"

/*
 * Care must be taken when using this since it WILL NOT be initialized when
 * audit_connection_from() is called and MAY NOT be initialized when
 * audit_event(CONNECTION_ABANDON) is called.  Test for NULL before using.
 */
ਬਾਹਰੀ Authctxt *the_authctxt;

/* Maybe add the audit class to struct Authmethod? */
ssh_audit_event_t
audit_classify_auth(ਅਚਲ ਅੱਖਰ *ਵਿਧੀ)
{
	ਜੇ (strcmp(ਵਿਧੀ, "none") == 0)
		ਵਾਪਸ SSH_AUTH_FAIL_NONE;
	ਨਹੀਂਤਾਂ ਜੇ (strcmp(ਵਿਧੀ, "password") == 0)
		ਵਾਪਸ SSH_AUTH_FAIL_PASSWD;
	ਨਹੀਂਤਾਂ ਜੇ (strcmp(ਵਿਧੀ, "publickey") == 0 ||
	    strcmp(ਵਿਧੀ, "rsa") == 0)
		ਵਾਪਸ SSH_AUTH_FAIL_PUBKEY;
	ਨਹੀਂਤਾਂ ਜੇ (ਲੜੀ_ਤੁਲਨਾ(ਵਿਧੀ, "keyboard-interactive", 20) == 0 ||
	    strcmp(ਵਿਧੀ, "challenge-response") == 0)
		ਵਾਪਸ SSH_AUTH_FAIL_KBDINT;
	ਨਹੀਂਤਾਂ ਜੇ (strcmp(ਵਿਧੀ, "hostbased") == 0 ||
	    strcmp(ਵਿਧੀ, "rhosts-rsa") == 0)
		ਵਾਪਸ SSH_AUTH_FAIL_HOSTBASED;
	ਨਹੀਂਤਾਂ ਜੇ (strcmp(ਵਿਧੀ, "gssapi-with-mic") == 0)
		ਵਾਪਸ SSH_AUTH_FAIL_GSSAPI;
	ਨਹੀਂਤਾਂ
		ਵਾਪਸ SSH_AUDIT_UNKNOWN;
}

/* helper to return supplied username */
ਅਚਲ ਅੱਖਰ *
audit_username(ਖਾਲੀ)
{
	ਸਥਿਰ ਅਚਲ ਅੱਖਰ unknownuser[] = "(unknown user)";
	ਸਥਿਰ ਅਚਲ ਅੱਖਰ invaliduser[] = "(invalid user)";

	ਜੇ (the_authctxt == ਨਿਰਾ || the_authctxt->user == ਨਿਰਾ)
		ਵਾਪਸ (unknownuser);
	ਜੇ (!the_authctxt->valid)
		ਵਾਪਸ (invaliduser);
	ਵਾਪਸ (the_authctxt->user);
}

ਅਚਲ ਅੱਖਰ *
audit_event_lookup(ssh_audit_event_t ev)
{
	ਪੂਰਨ i;
	ਸਥਿਰ ਬਣਤਰ event_lookup_struct {
		ssh_audit_event_t event;
		ਅਚਲ ਅੱਖਰ *name;
	} event_lookup[] = {
		{SSH_LOGIN_EXCEED_MAXTRIES,	"LOGIN_EXCEED_MAXTRIES"},
		{SSH_LOGIN_ਜੜ੍ਹ_DENIED,		"LOGIN_ROOT_DENIED"},
		{SSH_AUTH_SUCCESS,		"AUTH_SUCCESS"},
		{SSH_AUTH_FAIL_NONE,		"AUTH_FAIL_NONE"},
		{SSH_AUTH_FAIL_PASSWD,		"AUTH_FAIL_PASSWD"},
		{SSH_AUTH_FAIL_KBDINT,		"AUTH_FAIL_KBDINT"},
		{SSH_AUTH_FAIL_PUBKEY,		"AUTH_FAIL_PUBKEY"},
		{SSH_AUTH_FAIL_HOSTBASED,	"AUTH_FAIL_HOSTBASED"},
		{SSH_AUTH_FAIL_GSSAPI,		"AUTH_FAIL_GSSAPI"},
		{SSH_INVALID_USER,		"INVALID_USER"},
		{SSH_NOLOGIN,			"NOLOGIN"},
		{SSH_CONNECTION_CLOSE,		"CONNECTION_CLOSE"},
		{SSH_CONNECTION_ABANDON,	"CONNECTION_ABANDON"},
		{SSH_AUDIT_UNKNOWN,		"AUDIT_UNKNOWN"}
	};

	ਲਈ (i = 0; event_lookup[i].event != SSH_AUDIT_UNKNOWN; i++)
		ਜੇ (event_lookup[i].event == ev)
			ਰੋਕੋ;
	ਵਾਪਸ(event_lookup[i].name);
}

# ifndef CUSTOM_SSH_AUDIT_EVENTS
/*
 * Null implementations of audit functions.
 * These get used if SSH_AUDIT_EVENTS is defined but no audit module is enabled.
 */

/*
 * Called after a connection has been accepted but before any authentication
 * has been attempted.
 */
ਖਾਲੀ
audit_connection_from(ਅਚਲ ਅੱਖਰ *host, ਪੂਰਨ ਪੋਰਟ)
{
	debug("audit connection from %s port %d euid %d", host, ਪੋਰਟ,
	    (ਪੂਰਨ)geteuid());
}

/*
 * Called when various events occur (see audit.h for a list of possible
 * events and what they mean).
 */
ਖਾਲੀ
audit_event(ਬਣਤਰ ssh *ssh, ssh_audit_event_t event)
{
	debug("audit event euid %d user %s event %d (%s)", geteuid(),
	    audit_username(), event, audit_event_lookup(event));
}

/*
 * Called when a user session is started.  Argument is the tty allocated to
 * the session, or NULL if no tty was allocated.
 *
 * Note that this may be called multiple times if multiple sessions are used
 * within a single connection.
 */
ਖਾਲੀ
audit_session_open(ਬਣਤਰ logininfo *li)
{
	ਅਚਲ ਅੱਖਰ *t = li->ਸਤਰ ? li->ਸਤਰ : "(no tty)";

	debug("audit session open euid %d user %s tty name %s", geteuid(),
	    audit_username(), t);
}

/*
 * Called when a user session is closed.  Argument is the tty allocated to
 * the session, or NULL if no tty was allocated.
 *
 * Note that this may be called multiple times if multiple sessions are used
 * within a single connection.
 */
ਖਾਲੀ
audit_session_close(ਬਣਤਰ logininfo *li)
{
	ਅਚਲ ਅੱਖਰ *t = li->ਸਤਰ ? li->ਸਤਰ : "(no tty)";

	debug("audit session close euid %d user %s tty name %s", geteuid(),
	    audit_username(), t);
}

/*
 * This will be called when a user runs a non-interactive command.  Note that
 * it may be called multiple times for a single connection since SSH2 allows
 * multiple sessions within a single connection.
 */
ਖਾਲੀ
audit_ਲੜੀਵਾਰ_command(ਅਚਲ ਅੱਖਰ *command)
{
	debug("audit run command euid %d user %s command '%.200s'", geteuid(),
	    audit_username(), command);
}
# endif  /* !defined CUSTOM_SSH_AUDIT_EVENTS */
#ਜੇ_ਅੰਤ /* SSH_AUDIT_EVENTS */
