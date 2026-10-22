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

#شامل "includes.h"
#اگر defined(USE_LINUX_AUDIT)
#شامل <libaudit.h>
#شامل <unistd.h>
#شامل <string.h>

#شامل "log.h"
#شامل "audit.h"
#شامل "canohost.h"
#شامل "packet.h"

ثابت نویسه *audit_username(تهی);

صحیح
linux_audit_record_event(صحیح uid, ثابت نویسه *username, ثابت نویسه *hostname,
    ثابت نویسه *ip, ثابت نویسه *ttyn, صحیح success)
{
	صحیح audit_fd, rc, saved_errno;

	اگر ((audit_fd = audit_open()) < 0) {
		اگر (errno == EINVAL || errno == EPROTONOSUPPORT ||
		    errno == EAFNOSUPPORT)
			بازگشت 1; /* No audit support in kernel */
		وگرنه
			بازگشت 0; /* Must prevent login */
	}
        اگر (hostname != پوچ && strcmp(hostname, "UNKNOWN") == 0)
                hostname = پوچ;
	rc = audit_log_acct_message(audit_fd, AUDIT_USER_LOGIN,
	    پوچ, "login", username ? username : "(unknown)",
	    username == پوچ ? uid : -1, hostname, ip, ttyn, success);
	saved_errno = errno;
	close(audit_fd);

	/*
	 * Do not report error if the error is EPERM and sshd is run as non
	 * root user.
	 */
	اگر ((rc == -EPERM) && (geteuid() != 0))
		rc = 0;
	errno = saved_errno;

	بازگشت rc >= 0;
}

/* Below is the sshd audit API code */

تهی
audit_connection_from(ثابت نویسه *host, صحیح port)
{
	/* not implemented */
}

تهی
audit_run_command(ثابت نویسه *command)
{
	/* not implemented */
}

تهی
audit_session_open(ساختار logininfo *li)
{
	اگر (linux_audit_record_event(li->uid, پوچ, li->hostname, پوچ,
	    li->سطر, 1) == 0)
		fatal("linux_audit_write_entry failed: %s", strerror(errno));
}

تهی
audit_session_close(ساختار logininfo *li)
{
	/* not implemented */
}

تهی
audit_event(ساختار ssh *ssh, ssh_audit_event_t event)
{
	انتخاب(event) {
	حالت SSH_AUTH_SUCCESS:
	حالت SSH_CONNECTION_CLOSE:
	حالت SSH_NOLOGIN:
	حالت SSH_LOGIN_EXCEED_MAXTRIES:
	حالت SSH_LOGIN_ریشه_DENIED:
		بشکن;
	حالت SSH_AUTH_FAIL_NONE:
	حالت SSH_AUTH_FAIL_PASSWD:
	حالت SSH_AUTH_FAIL_KBDINT:
	حالت SSH_AUTH_FAIL_PUBKEY:
	حالت SSH_AUTH_FAIL_HOSTBASED:
	حالت SSH_AUTH_FAIL_GSSAPI:
	حالت SSH_INVALID_USER:
		linux_audit_record_event(-1, audit_username(), پوچ,
		    ssh_remote_ipaddr(ssh), "sshd", 0);
		بشکن;
	پیشفرض:
		debug_f("unhandled event %d", event);
		بشکن;
	}
}
#endif /* USE_LINUX_AUDIT */
