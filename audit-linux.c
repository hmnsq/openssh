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

#अन्तर्भाव "includes.h"
#जर defined(USE_LINUX_AUDIT)
#अन्तर्भाव <libaudit.h>
#अन्तर्भाव <unistd.h>
#अन्तर्भाव <string.h>

#अन्तर्भाव "log.h"
#अन्तर्भाव "audit.h"
#अन्तर्भाव "canohost.h"
#अन्तर्भाव "packet.h"

स्थिरांक अक्षर *audit_username(शून्य);

पूर्णांक
linux_audit_record_event(पूर्णांक uid, स्थिरांक अक्षर *username, स्थिरांक अक्षर *hostname,
    स्थिरांक अक्षर *ip, स्थिरांक अक्षर *ttyn, पूर्णांक success)
{
	पूर्णांक audit_fd, rc, saved_errno;

	जर ((audit_fd = audit_open()) < 0) {
		जर (त्रुटि_सं == EINVAL || त्रुटि_सं == EPROTONOSUPPORT ||
		    त्रुटि_सं == EAFNOSUPPORT)
			परत 1; /* No audit support in kernel */
		अन्यथा
			परत 0; /* Must prevent login */
	}
        जर (hostname != रिक्त && म_भेद(hostname, "UNKNOWN") == 0)
                hostname = रिक्त;
	rc = audit_log_acct_message(audit_fd, AUDIT_USER_LOGIN,
	    रिक्त, "login", username ? username : "(unknown)",
	    username == रिक्त ? uid : -1, hostname, ip, ttyn, success);
	saved_errno = त्रुटि_सं;
	बंद(audit_fd);

	/*
	 * Do not report error if the error is EPERM and sshd is run as non
	 * root user.
	 */
	जर ((rc == -EPERM) && (geteuid() != 0))
		rc = 0;
	त्रुटि_सं = saved_errno;

	परत rc >= 0;
}

/* Below is the sshd audit API code */

शून्य
audit_connection_from(स्थिरांक अक्षर *host, पूर्णांक port)
{
	/* not implemented */
}

शून्य
audit_run_command(स्थिरांक अक्षर *command)
{
	/* not implemented */
}

शून्य
audit_session_open(संरचना logininfo *li)
{
	जर (linux_audit_record_event(li->uid, रिक्त, li->hostname, रिक्त,
	    li->ओळ, 1) == 0)
		fatal("linux_audit_write_entry failed: %s", म_त्रुटि(त्रुटि_सं));
}

शून्य
audit_session_close(संरचना logininfo *li)
{
	/* not implemented */
}

शून्य
audit_event(संरचना ssh *ssh, ssh_audit_event_t event)
{
	निवड(event) {
	स्थिती SSH_AUTH_SUCCESS:
	स्थिती SSH_CONNECTION_CLOSE:
	स्थिती SSH_NOLOGIN:
	स्थिती SSH_LOGIN_EXCEED_MAXTRIES:
	स्थिती SSH_LOGIN_मूळ_DENIED:
		थांबा;
	स्थिती SSH_AUTH_FAIL_NONE:
	स्थिती SSH_AUTH_FAIL_PASSWD:
	स्थिती SSH_AUTH_FAIL_KBDINT:
	स्थिती SSH_AUTH_FAIL_PUBKEY:
	स्थिती SSH_AUTH_FAIL_HOSTBASED:
	स्थिती SSH_AUTH_FAIL_GSSAPI:
	स्थिती SSH_INVALID_USER:
		linux_audit_record_event(-1, audit_username(), रिक्त,
		    ssh_remote_ipaddr(ssh), "sshd", 0);
		थांबा;
	पूर्वनिर्धारित:
		debug_f("unhandled event %d", event);
		थांबा;
	}
}
#endif /* USE_LINUX_AUDIT */
