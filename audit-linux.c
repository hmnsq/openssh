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

#ଅନ୍ତର୍ଭାଵ "includes.h"
#ଯଦି defined(USE_LINUX_AUDIT)
#ଅନ୍ତର୍ଭାଵ <libaudit.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>
#ଅନ୍ତର୍ଭାଵ <string.h>

#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "audit.h"
#ଅନ୍ତର୍ଭାଵ "canohost.h"
#ଅନ୍ତର୍ଭାଵ "packet.h"

ଅଚଳ ଅକ୍ଷର *audit_username(ଶୂନ୍ୟ);

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
linux_audit_record_event(ପୂର୍ଣ୍ଣସଂଖ୍ୟା uid, ଅଚଳ ଅକ୍ଷର *username, ଅଚଳ ଅକ୍ଷର *hostname,
    ଅଚଳ ଅକ୍ଷର *ip, ଅଚଳ ଅକ୍ଷର *ttyn, ପୂର୍ଣ୍ଣସଂଖ୍ୟା success)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା audit_fd, rc, saved_errno;

	ଯଦି ((audit_fd = audit_open()) < 0) {
		ଯଦି (errno == EINVAL || errno == EPROTONOSUPPORT ||
		    errno == EAFNOSUPPORT)
			ଫେରନ୍ତୁ 1; /* No audit support in kernel */
		ଅନ୍ୟଥା
			ଫେରନ୍ତୁ 0; /* Must prevent login */
	}
        ଯଦି (hostname != ଖାଲି && strcmp(hostname, "UNKNOWN") == 0)
                hostname = ଖାଲି;
	rc = audit_log_acct_message(audit_fd, AUDIT_USER_LOGIN,
	    ଖାଲି, "login", username ? username : "(unknown)",
	    username == ଖାଲି ? uid : -1, hostname, ip, ttyn, success);
	saved_errno = errno;
	close(audit_fd);

	/*
	 * Do not report error if the error is EPERM and sshd is run as non
	 * root user.
	 */
	ଯଦି ((rc == -EPERM) && (geteuid() != 0))
		rc = 0;
	errno = saved_errno;

	ଫେରନ୍ତୁ rc >= 0;
}

/* Below is the sshd audit API code */

ଶୂନ୍ୟ
audit_connection_from(ଅଚଳ ଅକ୍ଷର *host, ପୂର୍ଣ୍ଣସଂଖ୍ୟା port)
{
	/* not implemented */
}

ଶୂନ୍ୟ
audit_run_command(ଅଚଳ ଅକ୍ଷର *command)
{
	/* not implemented */
}

ଶୂନ୍ୟ
audit_session_open(ସଂରଚନା logininfo *li)
{
	ଯଦି (linux_audit_record_event(li->uid, ଖାଲି, li->hostname, ଖାଲି,
	    li->ଧାଡ଼ି, 1) == 0)
		fatal("linux_audit_write_entry failed: %s", strerror(errno));
}

ଶୂନ୍ୟ
audit_session_close(ସଂରଚନା logininfo *li)
{
	/* not implemented */
}

ଶୂନ୍ୟ
audit_event(ସଂରଚନା ssh *ssh, ssh_audit_event_t event)
{
	ବାଛ(event) {
	ସ୍ଥିତି SSH_AUTH_SUCCESS:
	ସ୍ଥିତି SSH_CONNECTION_CLOSE:
	ସ୍ଥିତି SSH_NOLOGIN:
	ସ୍ଥିତି SSH_LOGIN_EXCEED_MAXTRIES:
	ସ୍ଥିତି SSH_LOGIN_ମୂଳ_DENIED:
		ଭାଙ୍ଗ;
	ସ୍ଥିତି SSH_AUTH_FAIL_NONE:
	ସ୍ଥିତି SSH_AUTH_FAIL_PASSWD:
	ସ୍ଥିତି SSH_AUTH_FAIL_KBDINT:
	ସ୍ଥିତି SSH_AUTH_FAIL_PUBKEY:
	ସ୍ଥିତି SSH_AUTH_FAIL_HOSTBASED:
	ସ୍ଥିତି SSH_AUTH_FAIL_GSSAPI:
	ସ୍ଥିତି SSH_INVALID_USER:
		linux_audit_record_event(-1, audit_username(), ଖାଲି,
		    ssh_remote_ipaddr(ssh), "sshd", 0);
		ଭାଙ୍ଗ;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		debug_f("unhandled event %d", event);
		ଭାଙ୍ଗ;
	}
}
#endif /* USE_LINUX_AUDIT */
