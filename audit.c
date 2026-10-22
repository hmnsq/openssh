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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <unistd.h>

#ifdef SSH_AUDIT_EVENTS

#અન્તર્ભાવ "audit.h"
#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "hostfile.h"
#અન્તર્ભાવ "auth.h"

/*
 * Care must be taken when using this since it WILL NOT be initialized when
 * audit_connection_from() is called and MAY NOT be initialized when
 * audit_event(CONNECTION_ABANDON) is called.  Test for NULL before using.
 */
બાહ્ય Authctxt *the_authctxt;

/* Maybe add the audit class to struct Authmethod? */
ssh_audit_event_t
audit_classify_auth(અચલ અક્ષર *method)
{
	જો (strcmp(method, "none") == 0)
		પાછા SSH_AUTH_FAIL_NONE;
	નહીંતર જો (strcmp(method, "password") == 0)
		પાછા SSH_AUTH_FAIL_PASSWD;
	નહીંતર જો (strcmp(method, "publickey") == 0 ||
	    strcmp(method, "rsa") == 0)
		પાછા SSH_AUTH_FAIL_PUBKEY;
	નહીંતર જો (strncmp(method, "keyboard-interactive", 20) == 0 ||
	    strcmp(method, "challenge-response") == 0)
		પાછા SSH_AUTH_FAIL_KBDINT;
	નહીંતર જો (strcmp(method, "hostbased") == 0 ||
	    strcmp(method, "rhosts-rsa") == 0)
		પાછા SSH_AUTH_FAIL_HOSTBASED;
	નહીંતર જો (strcmp(method, "gssapi-with-mic") == 0)
		પાછા SSH_AUTH_FAIL_GSSAPI;
	નહીંતર
		પાછા SSH_AUDIT_UNKNOWN;
}

/* helper to return supplied username */
અચલ અક્ષર *
audit_username(શૂન્ય)
{
	સ્થિર અચલ અક્ષર unknownuser[] = "(unknown user)";
	સ્થિર અચલ અક્ષર invaliduser[] = "(invalid user)";

	જો (the_authctxt == ખાલી || the_authctxt->user == ખાલી)
		પાછા (unknownuser);
	જો (!the_authctxt->valid)
		પાછા (invaliduser);
	પાછા (the_authctxt->user);
}

અચલ અક્ષર *
audit_event_lookup(ssh_audit_event_t ev)
{
	પૂર્ણાંક i;
	સ્થિર સંરચના event_lookup_struct {
		ssh_audit_event_t event;
		અચલ અક્ષર *name;
	} event_lookup[] = {
		{SSH_LOGIN_EXCEED_MAXTRIES,	"LOGIN_EXCEED_MAXTRIES"},
		{SSH_LOGIN_મૂળ_DENIED,		"LOGIN_ROOT_DENIED"},
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

	માટે (i = 0; event_lookup[i].event != SSH_AUDIT_UNKNOWN; i++)
		જો (event_lookup[i].event == ev)
			તોડો;
	પાછા(event_lookup[i].name);
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
શૂન્ય
audit_connection_from(અચલ અક્ષર *host, પૂર્ણાંક port)
{
	debug("audit connection from %s port %d euid %d", host, port,
	    (પૂર્ણાંક)geteuid());
}

/*
 * Called when various events occur (see audit.h for a list of possible
 * events and what they mean).
 */
શૂન્ય
audit_event(સંરચના ssh *ssh, ssh_audit_event_t event)
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
શૂન્ય
audit_session_open(સંરચના logininfo *li)
{
	અચલ અક્ષર *t = li->લીટી ? li->લીટી : "(no tty)";

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
શૂન્ય
audit_session_close(સંરચના logininfo *li)
{
	અચલ અક્ષર *t = li->લીટી ? li->લીટી : "(no tty)";

	debug("audit session close euid %d user %s tty name %s", geteuid(),
	    audit_username(), t);
}

/*
 * This will be called when a user runs a non-interactive command.  Note that
 * it may be called multiple times for a single connection since SSH2 allows
 * multiple sessions within a single connection.
 */
શૂન્ય
audit_run_command(અચલ અક્ષર *command)
{
	debug("audit run command euid %d user %s command '%.200s'", geteuid(),
	    audit_username(), command);
}
# endif  /* !defined CUSTOM_SSH_AUDIT_EVENTS */
#endif /* SSH_AUDIT_EVENTS */
