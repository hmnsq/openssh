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
#यदि defined(USE_LINUX_AUDIT)
#अन्तर्भाव <libaudit.h>
#अन्तर्भाव <unistd.h>
#अन्तर्भाव <string.h>

#अन्तर्भाव "log.h"
#अन्तर्भाव "audit.h"
#अन्तर्भाव "canohost.h"
#अन्तर्भाव "packet.h"

अचर वर्ण *audit_username(शून्य);

पूर्णाङ्क
linux_audit_record_event(पूर्णाङ्क uid, अचर वर्ण *username, अचर वर्ण *hostname,
    अचर वर्ण *ip, अचर वर्ण *ttyn, पूर्णाङ्क success)
{
	पूर्णाङ्क audit_fd, rc, saved_errno;

	यदि ((audit_fd = audit_open()) < 0) {
		यदि (त्रुटि_सं == EINVAL || त्रुटि_सं == EPROTONOSUPPORT ||
		    त्रुटि_सं == EAFNOSUPPORT)
			फर्काऊ 1; /* No audit support in kernel */
		अन्यथा
			फर्काऊ 0; /* Must prevent login */
	}
        यदि (hostname != रिक्त && म_भेद(hostname, "UNKNOWN") == 0)
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
	यदि ((rc == -EPERM) && (geteuid() != 0))
		rc = 0;
	त्रुटि_सं = saved_errno;

	फर्काऊ rc >= 0;
}

/* Below is the sshd audit API code */

शून्य
audit_connection_from(अचर वर्ण *host, पूर्णाङ्क port)
{
	/* not implemented */
}

शून्य
audit_run_command(अचर वर्ण *command)
{
	/* not implemented */
}

शून्य
audit_session_open(संरचना logininfo *li)
{
	यदि (linux_audit_record_event(li->uid, रिक्त, li->hostname, रिक्त,
	    li->पङ्क्ति, 1) == 0)
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
	विकल्प(event) {
	पक्ष SSH_AUTH_SUCCESS:
	पक्ष SSH_CONNECTION_CLOSE:
	पक्ष SSH_NOLOGIN:
	पक्ष SSH_LOGIN_EXCEED_MAXTRIES:
	पक्ष SSH_LOGIN_जरा_DENIED:
		रोक;
	पक्ष SSH_AUTH_FAIL_NONE:
	पक्ष SSH_AUTH_FAIL_PASSWD:
	पक्ष SSH_AUTH_FAIL_KBDINT:
	पक्ष SSH_AUTH_FAIL_PUBKEY:
	पक्ष SSH_AUTH_FAIL_HOSTBASED:
	पक्ष SSH_AUTH_FAIL_GSSAPI:
	पक्ष SSH_INVALID_USER:
		linux_audit_record_event(-1, audit_username(), रिक्त,
		    ssh_remote_ipaddr(ssh), "sshd", 0);
		रोक;
	स्वभाव:
		debug_f("unhandled event %d", event);
		रोक;
	}
}
#endif /* USE_LINUX_AUDIT */
