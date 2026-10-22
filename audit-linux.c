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

#অন্তর্ভাব "includes.h"
#যদি defined(USE_LINUX_AUDIT)
#অন্তর্ভাব <libaudit.h>
#অন্তর্ভাব <unistd.h>
#অন্তর্ভাব <string.h>

#অন্তর্ভাব "log.h"
#অন্তর্ভাব "audit.h"
#অন্তর্ভাব "canohost.h"
#অন্তর্ভাব "packet.h"

ধ্রুবক অক্ষর *audit_username(শূন্য);

পূর্ণসংখ্যা
linux_audit_record_event(পূর্ণসংখ্যা uid, ধ্রুবক অক্ষর *username, ধ্রুবক অক্ষর *hostname,
    ধ্রুবক অক্ষর *ip, ধ্রুবক অক্ষর *ttyn, পূর্ণসংখ্যা success)
{
	পূর্ণসংখ্যা audit_fd, rc, saved_errno;

	যদি ((audit_fd = audit_open()) < 0) {
		যদি (errno == EINVAL || errno == EPROTONOSUPPORT ||
		    errno == EAFNOSUPPORT)
			ফেরত 1; /* No audit support in kernel */
		অন্যথা
			ফেরত 0; /* Must prevent login */
	}
        যদি (hostname != ফাঁকা && strcmp(hostname, "UNKNOWN") == 0)
                hostname = ফাঁকা;
	rc = audit_log_acct_message(audit_fd, AUDIT_USER_LOGIN,
	    ফাঁকা, "login", username ? username : "(unknown)",
	    username == ফাঁকা ? uid : -1, hostname, ip, ttyn, success);
	saved_errno = errno;
	close(audit_fd);

	/*
	 * Do not report error if the error is EPERM and sshd is run as non
	 * root user.
	 */
	যদি ((rc == -EPERM) && (geteuid() != 0))
		rc = 0;
	errno = saved_errno;

	ফেরত rc >= 0;
}

/* Below is the sshd audit API code */

শূন্য
audit_connection_from(ধ্রুবক অক্ষর *host, পূর্ণসংখ্যা port)
{
	/* not implemented */
}

শূন্য
audit_run_command(ধ্রুবক অক্ষর *command)
{
	/* not implemented */
}

শূন্য
audit_session_open(কাঠামো logininfo *li)
{
	যদি (linux_audit_record_event(li->uid, ফাঁকা, li->hostname, ফাঁকা,
	    li->সারি, 1) == 0)
		fatal("linux_audit_write_entry failed: %s", strerror(errno));
}

শূন্য
audit_session_close(কাঠামো logininfo *li)
{
	/* not implemented */
}

শূন্য
audit_event(কাঠামো ssh *ssh, ssh_audit_event_t event)
{
	নির্বাচন(event) {
	ক্ষেত্র SSH_AUTH_SUCCESS:
	ক্ষেত্র SSH_CONNECTION_CLOSE:
	ক্ষেত্র SSH_NOLOGIN:
	ক্ষেত্র SSH_LOGIN_EXCEED_MAXTRIES:
	ক্ষেত্র SSH_LOGIN_মূল_DENIED:
		বিরতি;
	ক্ষেত্র SSH_AUTH_FAIL_NONE:
	ক্ষেত্র SSH_AUTH_FAIL_PASSWD:
	ক্ষেত্র SSH_AUTH_FAIL_KBDINT:
	ক্ষেত্র SSH_AUTH_FAIL_PUBKEY:
	ক্ষেত্র SSH_AUTH_FAIL_HOSTBASED:
	ক্ষেত্র SSH_AUTH_FAIL_GSSAPI:
	ক্ষেত্র SSH_INVALID_USER:
		linux_audit_record_event(-1, audit_username(), ফাঁকা,
		    ssh_remote_ipaddr(ssh), "sshd", 0);
		বিরতি;
	পূর্বনির্ধারিত:
		debug_f("unhandled event %d", event);
		বিরতি;
	}
}
#endif /* USE_LINUX_AUDIT */
