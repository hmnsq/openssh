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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <stdarg.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>

#ifdef SSH_AUDIT_EVENTS

#ଅନ୍ତର୍ଭାଵ "audit.h"
#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "hostfile.h"
#ଅନ୍ତର୍ଭାଵ "auth.h"

/*
 * Care must be taken when using this since it WILL NOT be initialized when
 * audit_connection_from() is called and MAY NOT be initialized when
 * audit_event(CONNECTION_ABANDON) is called.  Test for NULL before using.
 */
ବାହ୍ୟ Authctxt *the_authctxt;

/* Maybe add the audit class to struct Authmethod? */
ssh_audit_event_t
audit_classify_auth(ଅଚଳ ଅକ୍ଷର *method)
{
	ଯଦି (strcmp(method, "none") == 0)
		ଫେରନ୍ତୁ SSH_AUTH_FAIL_NONE;
	ଅନ୍ୟଥା ଯଦି (strcmp(method, "password") == 0)
		ଫେରନ୍ତୁ SSH_AUTH_FAIL_PASSWD;
	ଅନ୍ୟଥା ଯଦି (strcmp(method, "publickey") == 0 ||
	    strcmp(method, "rsa") == 0)
		ଫେରନ୍ତୁ SSH_AUTH_FAIL_PUBKEY;
	ଅନ୍ୟଥା ଯଦି (strncmp(method, "keyboard-interactive", 20) == 0 ||
	    strcmp(method, "challenge-response") == 0)
		ଫେରନ୍ତୁ SSH_AUTH_FAIL_KBDINT;
	ଅନ୍ୟଥା ଯଦି (strcmp(method, "hostbased") == 0 ||
	    strcmp(method, "rhosts-rsa") == 0)
		ଫେରନ୍ତୁ SSH_AUTH_FAIL_HOSTBASED;
	ଅନ୍ୟଥା ଯଦି (strcmp(method, "gssapi-with-mic") == 0)
		ଫେରନ୍ତୁ SSH_AUTH_FAIL_GSSAPI;
	ଅନ୍ୟଥା
		ଫେରନ୍ତୁ SSH_AUDIT_UNKNOWN;
}

/* helper to return supplied username */
ଅଚଳ ଅକ୍ଷର *
audit_username(ଶୂନ୍ୟ)
{
	ସ୍ଥିର ଅଚଳ ଅକ୍ଷର unknownuser[] = "(unknown user)";
	ସ୍ଥିର ଅଚଳ ଅକ୍ଷର invaliduser[] = "(invalid user)";

	ଯଦି (the_authctxt == ଖାଲି || the_authctxt->user == ଖାଲି)
		ଫେରନ୍ତୁ (unknownuser);
	ଯଦି (!the_authctxt->valid)
		ଫେରନ୍ତୁ (invaliduser);
	ଫେରନ୍ତୁ (the_authctxt->user);
}

ଅଚଳ ଅକ୍ଷର *
audit_event_lookup(ssh_audit_event_t ev)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;
	ସ୍ଥିର ସଂରଚନା event_lookup_struct {
		ssh_audit_event_t event;
		ଅଚଳ ଅକ୍ଷର *name;
	} event_lookup[] = {
		{SSH_LOGIN_EXCEED_MAXTRIES,	"LOGIN_EXCEED_MAXTRIES"},
		{SSH_LOGIN_ମୂଳ_DENIED,		"LOGIN_ROOT_DENIED"},
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

	ପାଇଁ (i = 0; event_lookup[i].event != SSH_AUDIT_UNKNOWN; i++)
		ଯଦି (event_lookup[i].event == ev)
			ଭାଙ୍ଗ;
	ଫେରନ୍ତୁ(event_lookup[i].name);
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
ଶୂନ୍ୟ
audit_connection_from(ଅଚଳ ଅକ୍ଷର *host, ପୂର୍ଣ୍ଣସଂଖ୍ୟା port)
{
	debug("audit connection from %s port %d euid %d", host, port,
	    (ପୂର୍ଣ୍ଣସଂଖ୍ୟା)geteuid());
}

/*
 * Called when various events occur (see audit.h for a list of possible
 * events and what they mean).
 */
ଶୂନ୍ୟ
audit_event(ସଂରଚନା ssh *ssh, ssh_audit_event_t event)
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
ଶୂନ୍ୟ
audit_session_open(ସଂରଚନା logininfo *li)
{
	ଅଚଳ ଅକ୍ଷର *t = li->ଧାଡ଼ି ? li->ଧାଡ଼ି : "(no tty)";

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
ଶୂନ୍ୟ
audit_session_close(ସଂରଚନା logininfo *li)
{
	ଅଚଳ ଅକ୍ଷର *t = li->ଧାଡ଼ି ? li->ଧାଡ଼ି : "(no tty)";

	debug("audit session close euid %d user %s tty name %s", geteuid(),
	    audit_username(), t);
}

/*
 * This will be called when a user runs a non-interactive command.  Note that
 * it may be called multiple times for a single connection since SSH2 allows
 * multiple sessions within a single connection.
 */
ଶୂନ୍ୟ
audit_run_command(ଅଚଳ ଅକ୍ଷର *command)
{
	debug("audit run command euid %d user %s command '%.200s'", geteuid(),
	    audit_username(), command);
}
# endif  /* !defined CUSTOM_SSH_AUDIT_EVENTS */
#endif /* SSH_AUDIT_EVENTS */
