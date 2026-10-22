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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>

#ifdef SSH_AUDIT_EVENTS

#ಅನ್ತರ್ಭಾವ "audit.h"
#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "hostfile.h"
#ಅನ್ತರ್ಭಾವ "auth.h"

/*
 * Care must be taken when using this since it WILL NOT be initialized when
 * audit_connection_from() is called and MAY NOT be initialized when
 * audit_event(CONNECTION_ABANDON) is called.  Test for NULL before using.
 */
ಬಾಹ್ಯ Authctxt *the_authctxt;

/* Maybe add the audit class to struct Authmethod? */
ssh_audit_event_t
audit_classify_auth(ಧ್ರುವ ವರ್ಣ *method)
{
	ಯದಿ (strcmp(method, "none") == 0)
		ಪ್ರತ್ಯಾಗಮ SSH_AUTH_FAIL_NONE;
	ಅನ್ಯಥಾ ಯದಿ (strcmp(method, "password") == 0)
		ಪ್ರತ್ಯಾಗಮ SSH_AUTH_FAIL_PASSWD;
	ಅನ್ಯಥಾ ಯದಿ (strcmp(method, "publickey") == 0 ||
	    strcmp(method, "rsa") == 0)
		ಪ್ರತ್ಯಾಗಮ SSH_AUTH_FAIL_PUBKEY;
	ಅನ್ಯಥಾ ಯದಿ (strncmp(method, "keyboard-interactive", 20) == 0 ||
	    strcmp(method, "challenge-response") == 0)
		ಪ್ರತ್ಯಾಗಮ SSH_AUTH_FAIL_KBDINT;
	ಅನ್ಯಥಾ ಯದಿ (strcmp(method, "hostbased") == 0 ||
	    strcmp(method, "rhosts-rsa") == 0)
		ಪ್ರತ್ಯಾಗಮ SSH_AUTH_FAIL_HOSTBASED;
	ಅನ್ಯಥಾ ಯದಿ (strcmp(method, "gssapi-with-mic") == 0)
		ಪ್ರತ್ಯಾಗಮ SSH_AUTH_FAIL_GSSAPI;
	ಅನ್ಯಥಾ
		ಪ್ರತ್ಯಾಗಮ SSH_AUDIT_UNKNOWN;
}

/* helper to return supplied username */
ಧ್ರುವ ವರ್ಣ *
audit_username(ಶೂನ್ಯ)
{
	ಸ್ಥಿರ ಧ್ರುವ ವರ್ಣ unknownuser[] = "(unknown user)";
	ಸ್ಥಿರ ಧ್ರುವ ವರ್ಣ invaliduser[] = "(invalid user)";

	ಯದಿ (the_authctxt == ರಿಕ್ತ || the_authctxt->user == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ (unknownuser);
	ಯದಿ (!the_authctxt->valid)
		ಪ್ರತ್ಯಾಗಮ (invaliduser);
	ಪ್ರತ್ಯಾಗಮ (the_authctxt->user);
}

ಧ್ರುವ ವರ್ಣ *
audit_event_lookup(ssh_audit_event_t ev)
{
	ಪೂರ್ಣಾಙ್ಕ i;
	ಸ್ಥಿರ ಸಂರಚನಾ event_lookup_struct {
		ssh_audit_event_t event;
		ಧ್ರುವ ವರ್ಣ *name;
	} event_lookup[] = {
		{SSH_LOGIN_EXCEED_MAXTRIES,	"LOGIN_EXCEED_MAXTRIES"},
		{SSH_LOGIN_ಬೇರು_DENIED,		"LOGIN_ROOT_DENIED"},
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

	ಪ್ರತಿ (i = 0; event_lookup[i].event != SSH_AUDIT_UNKNOWN; i++)
		ಯದಿ (event_lookup[i].event == ev)
			ಭಙ್ಗ;
	ಪ್ರತ್ಯಾಗಮ(event_lookup[i].name);
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
ಶೂನ್ಯ
audit_connection_from(ಧ್ರುವ ವರ್ಣ *host, ಪೂರ್ಣಾಙ್ಕ port)
{
	debug("audit connection from %s port %d euid %d", host, port,
	    (ಪೂರ್ಣಾಙ್ಕ)geteuid());
}

/*
 * Called when various events occur (see audit.h for a list of possible
 * events and what they mean).
 */
ಶೂನ್ಯ
audit_event(ಸಂರಚನಾ ssh *ssh, ssh_audit_event_t event)
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
ಶೂನ್ಯ
audit_session_open(ಸಂರಚನಾ logininfo *li)
{
	ಧ್ರುವ ವರ್ಣ *t = li->ಸಾಲು ? li->ಸಾಲು : "(no tty)";

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
ಶೂನ್ಯ
audit_session_close(ಸಂರಚನಾ logininfo *li)
{
	ಧ್ರುವ ವರ್ಣ *t = li->ಸಾಲು ? li->ಸಾಲು : "(no tty)";

	debug("audit session close euid %d user %s tty name %s", geteuid(),
	    audit_username(), t);
}

/*
 * This will be called when a user runs a non-interactive command.  Note that
 * it may be called multiple times for a single connection since SSH2 allows
 * multiple sessions within a single connection.
 */
ಶೂನ್ಯ
audit_run_command(ಧ್ರುವ ವರ್ಣ *command)
{
	debug("audit run command euid %d user %s command '%.200s'", geteuid(),
	    audit_username(), command);
}
# endif  /* !defined CUSTOM_SSH_AUDIT_EVENTS */
#endif /* SSH_AUDIT_EVENTS */
