/*
 * Copyright 2010 Red Hat, Inc.  All rights reserved.
 * Use is subject to license terms.
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
 *
 * Red Hat author: Jan F. Chadima <jchadima@redhat.com>
 */

#समावेश "includes.h"
#अगर defined(USE_LINUX_AUDIT)
#समावेश <libaudit.h>
#समावेश <unistd.h>
#समावेश <string.h>

#समावेश "log.h"
#समावेश "audit.h"
#समावेश "canohost.h"
#समावेश "packet.h"

स्थिर अक्षर *audit_username(व्योम);

पूर्णांक
linux_audit_record_event(पूर्णांक uid, स्थिर अक्षर *username, स्थिर अक्षर *hostname,
    स्थिर अक्षर *ip, स्थिर अक्षर *ttyn, पूर्णांक success)
{
	पूर्णांक audit_fd, rc, saved_errno;

	अगर ((audit_fd = audit_open()) < 0) {
		अगर (त्रुटि_सं == EINVAL || त्रुटि_सं == EPROTONOSUPPORT ||
		    त्रुटि_सं == EAFNOSUPPORT)
			वापस 1; /* No audit support in kernel */
		अन्यथा
			वापस 0; /* Must prevent login */
	}
        अगर (hostname != शून्य && म_भेद(hostname, "UNKNOWN") == 0)
                hostname = शून्य;
	rc = audit_log_acct_message(audit_fd, AUDIT_USER_LOGIN,
	    शून्य, "login", username ? username : "(unknown)",
	    username == शून्य ? uid : -1, hostname, ip, ttyn, success);
	saved_errno = त्रुटि_सं;
	बंद(audit_fd);

	/*
	 * Do not report error if the error is EPERM and sshd is run as non
	 * root user.
	 */
	अगर ((rc == -EPERM) && (geteuid() != 0))
		rc = 0;
	त्रुटि_सं = saved_errno;

	वापस rc >= 0;
}

/* Below is the sshd audit API code */

व्योम
audit_connection_from(स्थिर अक्षर *host, पूर्णांक port)
{
	/* not implemented */
}

व्योम
audit_run_command(स्थिर अक्षर *command)
{
	/* not implemented */
}

व्योम
audit_session_open(काष्ठा logininfo *li)
{
	अगर (linux_audit_record_event(li->uid, शून्य, li->hostname, शून्य,
	    li->पंक्ति, 1) == 0)
		fatal("linux_audit_write_entry failed: %s", म_त्रुटि(त्रुटि_सं));
}

व्योम
audit_session_close(काष्ठा logininfo *li)
{
	/* not implemented */
}

व्योम
audit_event(काष्ठा ssh *ssh, ssh_audit_event_t event)
{
	चयन(event) {
	हाल SSH_AUTH_SUCCESS:
	हाल SSH_CONNECTION_CLOSE:
	हाल SSH_NOLOGIN:
	हाल SSH_LOGIN_EXCEED_MAXTRIES:
	हाल SSH_LOGIN_मूल_DENIED:
		अवरोध;
	हाल SSH_AUTH_FAIL_NONE:
	हाल SSH_AUTH_FAIL_PASSWD:
	हाल SSH_AUTH_FAIL_KBDINT:
	हाल SSH_AUTH_FAIL_PUBKEY:
	हाल SSH_AUTH_FAIL_HOSTBASED:
	हाल SSH_AUTH_FAIL_GSSAPI:
	हाल SSH_INVALID_USER:
		linux_audit_record_event(-1, audit_username(), शून्य,
		    ssh_remote_ipaddr(ssh), "sshd", 0);
		अवरोध;
	शेष:
		debug_f("unhandled event %d", event);
		अवरोध;
	}
}
#पूर्ण_अगर /* USE_LINUX_AUDIT */
