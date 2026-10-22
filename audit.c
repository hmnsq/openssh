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

#समावेश "includes.h"

#समावेश <stdarg.h>
#समावेश <string.h>
#समावेश <unistd.h>

#अगर_घोषित SSH_AUDIT_EVENTS

#समावेश "audit.h"
#समावेश "log.h"
#समावेश "hostfile.h"
#समावेश "auth.h"

/*
 * Care must be taken when using this since it WILL NOT be initialized when
 * audit_connection_from() is called and MAY NOT be initialized when
 * audit_event(CONNECTION_ABANDON) is called.  Test for NULL before using.
 */
बाह्य Authctxt *the_authctxt;

/* Maybe add the audit class to struct Authmethod? */
ssh_audit_event_t
audit_classify_auth(स्थिर अक्षर *method)
{
	अगर (म_भेद(method, "none") == 0)
		वापस SSH_AUTH_FAIL_NONE;
	अन्यथा अगर (म_भेद(method, "password") == 0)
		वापस SSH_AUTH_FAIL_PASSWD;
	अन्यथा अगर (म_भेद(method, "publickey") == 0 ||
	    म_भेद(method, "rsa") == 0)
		वापस SSH_AUTH_FAIL_PUBKEY;
	अन्यथा अगर (म_भेदन(method, "keyboard-interactive", 20) == 0 ||
	    म_भेद(method, "challenge-response") == 0)
		वापस SSH_AUTH_FAIL_KBDINT;
	अन्यथा अगर (म_भेद(method, "hostbased") == 0 ||
	    म_भेद(method, "rhosts-rsa") == 0)
		वापस SSH_AUTH_FAIL_HOSTBASED;
	अन्यथा अगर (म_भेद(method, "gssapi-with-mic") == 0)
		वापस SSH_AUTH_FAIL_GSSAPI;
	अन्यथा
		वापस SSH_AUDIT_UNKNOWN;
}

/* helper to return supplied username */
स्थिर अक्षर *
audit_username(व्योम)
{
	अटल स्थिर अक्षर unknownuser[] = "(unknown user)";
	अटल स्थिर अक्षर invaliduser[] = "(invalid user)";

	अगर (the_authctxt == शून्य || the_authctxt->user == शून्य)
		वापस (unknownuser);
	अगर (!the_authctxt->valid)
		वापस (invaliduser);
	वापस (the_authctxt->user);
}

स्थिर अक्षर *
audit_event_lookup(ssh_audit_event_t ev)
{
	पूर्णांक i;
	अटल काष्ठा event_lookup_struct {
		ssh_audit_event_t event;
		स्थिर अक्षर *name;
	} event_lookup[] = {
		{SSH_LOGIN_EXCEED_MAXTRIES,	"LOGIN_EXCEED_MAXTRIES"},
		{SSH_LOGIN_मूल_DENIED,		"LOGIN_ROOT_DENIED"},
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

	क्रम (i = 0; event_lookup[i].event != SSH_AUDIT_UNKNOWN; i++)
		अगर (event_lookup[i].event == ev)
			अवरोध;
	वापस(event_lookup[i].name);
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
व्योम
audit_connection_from(स्थिर अक्षर *host, पूर्णांक port)
{
	debug("audit connection from %s port %d euid %d", host, port,
	    (पूर्णांक)geteuid());
}

/*
 * Called when various events occur (see audit.h for a list of possible
 * events and what they mean).
 */
व्योम
audit_event(काष्ठा ssh *ssh, ssh_audit_event_t event)
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
व्योम
audit_session_open(काष्ठा logininfo *li)
{
	स्थिर अक्षर *t = li->पंक्ति ? li->पंक्ति : "(no tty)";

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
व्योम
audit_session_close(काष्ठा logininfo *li)
{
	स्थिर अक्षर *t = li->पंक्ति ? li->पंक्ति : "(no tty)";

	debug("audit session close euid %d user %s tty name %s", geteuid(),
	    audit_username(), t);
}

/*
 * This will be called when a user runs a non-interactive command.  Note that
 * it may be called multiple times for a single connection since SSH2 allows
 * multiple sessions within a single connection.
 */
व्योम
audit_run_command(स्थिर अक्षर *command)
{
	debug("audit run command euid %d user %s command '%.200s'", geteuid(),
	    audit_username(), command);
}
# endif  /* !defined CUSTOM_SSH_AUDIT_EVENTS */
#पूर्ण_अगर /* SSH_AUDIT_EVENTS */
