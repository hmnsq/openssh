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

#ضمن "includes.h"
#إذا defined(USE_LINUX_AUDIT)
#ضمن <libaudit.h>
#ضمن <unistd.h>
#ضمن <string.h>

#ضمن "log.h"
#ضمن "audit.h"
#ضمن "canohost.h"
#ضمن "packet.h"

ثابت حرف *audit_username(فراغ);

صحيح
linux_audit_record_event(صحيح uid, ثابت حرف *username, ثابت حرف *hostname,
    ثابت حرف *ip, ثابت حرف *ttyn, صحيح success)
{
	صحيح audit_fd, rc, saved_errno;

	إذا ((audit_fd = audit_open()) < 0) {
		إذا (errno == EINVAL || errno == EPROTONOSUPPORT ||
		    errno == EAFNOSUPPORT)
			إرجاع 1; /* No audit support in kernel */
		وإلا
			إرجاع 0; /* Must prevent login */
	}
        إذا (hostname != عدم && strcmp(hostname, "UNKNOWN") == 0)
                hostname = عدم;
	rc = audit_log_acct_message(audit_fd, AUDIT_USER_LOGIN,
	    عدم, "login", username ? username : "(unknown)",
	    username == عدم ? uid : -1, hostname, ip, ttyn, success);
	saved_errno = errno;
	close(audit_fd);

	/*
	 * Do not report error if the error is EPERM and sshd is run as non
	 * root user.
	 */
	إذا ((rc == -EPERM) && (geteuid() != 0))
		rc = 0;
	errno = saved_errno;

	إرجاع rc >= 0;
}

/* Below is the sshd audit API code */

فراغ
audit_connection_from(ثابت حرف *host, صحيح port)
{
	/* not implemented */
}

فراغ
audit_run_command(ثابت حرف *command)
{
	/* not implemented */
}

فراغ
audit_session_open(بنية logininfo *li)
{
	إذا (linux_audit_record_event(li->uid, عدم, li->hostname, عدم,
	    li->سطر, 1) == 0)
		fatal("linux_audit_write_entry failed: %s", strerror(errno));
}

فراغ
audit_session_close(بنية logininfo *li)
{
	/* not implemented */
}

فراغ
audit_event(بنية ssh *ssh, ssh_audit_event_t event)
{
	بدل(event) {
	حالة SSH_AUTH_SUCCESS:
	حالة SSH_CONNECTION_CLOSE:
	حالة SSH_NOLOGIN:
	حالة SSH_LOGIN_EXCEED_MAXTRIES:
	حالة SSH_LOGIN_جذر_DENIED:
		اكسر;
	حالة SSH_AUTH_FAIL_NONE:
	حالة SSH_AUTH_FAIL_PASSWD:
	حالة SSH_AUTH_FAIL_KBDINT:
	حالة SSH_AUTH_FAIL_PUBKEY:
	حالة SSH_AUTH_FAIL_HOSTBASED:
	حالة SSH_AUTH_FAIL_GSSAPI:
	حالة SSH_INVALID_USER:
		linux_audit_record_event(-1, audit_username(), عدم,
		    ssh_remote_ipaddr(ssh), "sshd", 0);
		اكسر;
	افتراضي:
		debug_f("unhandled event %d", event);
		اكسر;
	}
}
#endif /* USE_LINUX_AUDIT */
