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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <unistd.h>

#నిర్వచితమైతే SSH_AUDIT_EVENTS

#అన్తర్భావ "audit.h"
#అన్తర్భావ "log.h"
#అన్తర్భావ "hostfile.h"
#అన్తర్భావ "auth.h"

/*
 * Care must be taken when using this since it WILL NOT be initialized when
 * audit_connection_from() is called and MAY NOT be initialized when
 * audit_event(CONNECTION_ABANDON) is called.  Test for NULL before using.
 */
బాహ్య Authctxt *the_authctxt;

/* Maybe add the audit class to struct Authmethod? */
ssh_audit_event_t
audit_classify_auth(స్థిరరాశి అక్షరం *పద్ధతి)
{
	ఒకవేళ (strcmp(పద్ధతి, "none") == 0)
		తిరిగి SSH_AUTH_FAIL_NONE;
	లేకపోతే ఒకవేళ (strcmp(పద్ధతి, "password") == 0)
		తిరిగి SSH_AUTH_FAIL_PASSWD;
	లేకపోతే ఒకవేళ (strcmp(పద్ధతి, "publickey") == 0 ||
	    strcmp(పద్ధతి, "rsa") == 0)
		తిరిగి SSH_AUTH_FAIL_PUBKEY;
	లేకపోతే ఒకవేళ (అక్షరశ్రేణి_పోలిక(పద్ధతి, "keyboard-interactive", 20) == 0 ||
	    strcmp(పద్ధతి, "challenge-response") == 0)
		తిరిగి SSH_AUTH_FAIL_KBDINT;
	లేకపోతే ఒకవేళ (strcmp(పద్ధతి, "hostbased") == 0 ||
	    strcmp(పద్ధతి, "rhosts-rsa") == 0)
		తిరిగి SSH_AUTH_FAIL_HOSTBASED;
	లేకపోతే ఒకవేళ (strcmp(పద్ధతి, "gssapi-with-mic") == 0)
		తిరిగి SSH_AUTH_FAIL_GSSAPI;
	లేకపోతే
		తిరిగి SSH_AUDIT_UNKNOWN;
}

/* helper to return supplied username */
స్థిరరాశి అక్షరం *
audit_username(శూన్య)
{
	స్థిర స్థిరరాశి అక్షరం unknownuser[] = "(unknown user)";
	స్థిర స్థిరరాశి అక్షరం invaliduser[] = "(invalid user)";

	ఒకవేళ (the_authctxt == ఖాళీ || the_authctxt->user == ఖాళీ)
		తిరిగి (unknownuser);
	ఒకవేళ (!the_authctxt->valid)
		తిరిగి (invaliduser);
	తిరిగి (the_authctxt->user);
}

స్థిరరాశి అక్షరం *
audit_event_lookup(ssh_audit_event_t ev)
{
	పూర్ణాంకం i;
	స్థిర నిర్మాణం event_lookup_struct {
		ssh_audit_event_t event;
		స్థిరరాశి అక్షరం *name;
	} event_lookup[] = {
		{SSH_LOGIN_EXCEED_MAXTRIES,	"LOGIN_EXCEED_MAXTRIES"},
		{SSH_LOGIN_మూలం_DENIED,		"LOGIN_ROOT_DENIED"},
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

	కొరకు (i = 0; event_lookup[i].event != SSH_AUDIT_UNKNOWN; i++)
		ఒకవేళ (event_lookup[i].event == ev)
			ఆపు;
	తిరిగి(event_lookup[i].name);
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
శూన్య
audit_connection_from(స్థిరరాశి అక్షరం *host, పూర్ణాంకం పోర్టు)
{
	debug("audit connection from %s port %d euid %d", host, పోర్టు,
	    (పూర్ణాంకం)geteuid());
}

/*
 * Called when various events occur (see audit.h for a list of possible
 * events and what they mean).
 */
శూన్య
audit_event(నిర్మాణం ssh *ssh, ssh_audit_event_t event)
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
శూన్య
audit_session_open(నిర్మాణం logininfo *li)
{
	స్థిరరాశి అక్షరం *t = li->పంక్తి ? li->పంక్తి : "(no tty)";

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
శూన్య
audit_session_close(నిర్మాణం logininfo *li)
{
	స్థిరరాశి అక్షరం *t = li->పంక్తి ? li->పంక్తి : "(no tty)";

	debug("audit session close euid %d user %s tty name %s", geteuid(),
	    audit_username(), t);
}

/*
 * This will be called when a user runs a non-interactive command.  Note that
 * it may be called multiple times for a single connection since SSH2 allows
 * multiple sessions within a single connection.
 */
శూన్య
audit_నిరంతరం_command(స్థిరరాశి అక్షరం *command)
{
	debug("audit run command euid %d user %s command '%.200s'", geteuid(),
	    audit_username(), command);
}
# endif  /* !defined CUSTOM_SSH_AUDIT_EVENTS */
#అయితే_ముగింపు /* SSH_AUDIT_EVENTS */
