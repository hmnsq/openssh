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

#অন্তর্ভাৱ "includes.h"
#যদি defined(USE_LINUX_AUDIT)
#অন্তর্ভাৱ <libaudit.h>
#অন্তর্ভাৱ <unistd.h>
#অন্তর্ভাৱ <string.h>

#অন্তর্ভাৱ "log.h"
#অন্তর্ভাৱ "audit.h"
#অন্তর্ভাৱ "canohost.h"
#অন্তর্ভাৱ "packet.h"

ধ্রুৱ ৱর্ণ *audit_username(শূন্য);

পূর্ণাঙ্ক
linux_audit_record_event(পূর্ণাঙ্ক uid, ধ্রুৱ ৱর্ণ *username, ধ্রুৱ ৱর্ণ *hostname,
    ধ্রুৱ ৱর্ণ *ip, ধ্রুৱ ৱর্ণ *ttyn, পূর্ণাঙ্ক success)
{
	পূর্ণাঙ্ক audit_fd, rc, saved_errno;

	যদি ((audit_fd = audit_open()) < 0) {
		যদি (errno == EINVAL || errno == EPROTONOSUPPORT ||
		    errno == EAFNOSUPPORT)
			ঘূৰাই 1; /* No audit support in kernel */
		অন্যথা
			ঘূৰাই 0; /* Must prevent login */
	}
        যদি (hostname != রিক্ত && strcmp(hostname, "UNKNOWN") == 0)
                hostname = রিক্ত;
	rc = audit_log_acct_message(audit_fd, AUDIT_USER_LOGIN,
	    রিক্ত, "login", username ? username : "(unknown)",
	    username == রিক্ত ? uid : -1, hostname, ip, ttyn, success);
	saved_errno = errno;
	close(audit_fd);

	/*
	 * Do not report error if the error is EPERM and sshd is run as non
	 * root user.
	 */
	যদি ((rc == -EPERM) && (geteuid() != 0))
		rc = 0;
	errno = saved_errno;

	ঘূৰাই rc >= 0;
}

/* Below is the sshd audit API code */

শূন্য
audit_connection_from(ধ্রুৱ ৱর্ণ *host, পূর্ণাঙ্ক port)
{
	/* not implemented */
}

শূন্য
audit_run_command(ধ্রুৱ ৱর্ণ *command)
{
	/* not implemented */
}

শূন্য
audit_session_open(সংরচনা logininfo *li)
{
	যদি (linux_audit_record_event(li->uid, রিক্ত, li->hostname, রিক্ত,
	    li->সাৰি, 1) == 0)
		fatal("linux_audit_write_entry failed: %s", strerror(errno));
}

শূন্য
audit_session_close(সংরচনা logininfo *li)
{
	/* not implemented */
}

শূন্য
audit_event(সংরচনা ssh *ssh, ssh_audit_event_t event)
{
	ৱিকল্প(event) {
	পক্ষ SSH_AUTH_SUCCESS:
	পক্ষ SSH_CONNECTION_CLOSE:
	পক্ষ SSH_NOLOGIN:
	পক্ষ SSH_LOGIN_EXCEED_MAXTRIES:
	পক্ষ SSH_LOGIN_মূল_DENIED:
		ভঙ্গ;
	পক্ষ SSH_AUTH_FAIL_NONE:
	পক্ষ SSH_AUTH_FAIL_PASSWD:
	পক্ষ SSH_AUTH_FAIL_KBDINT:
	পক্ষ SSH_AUTH_FAIL_PUBKEY:
	পক্ষ SSH_AUTH_FAIL_HOSTBASED:
	পক্ষ SSH_AUTH_FAIL_GSSAPI:
	পক্ষ SSH_INVALID_USER:
		linux_audit_record_event(-1, audit_username(), রিক্ত,
		    ssh_remote_ipaddr(ssh), "sshd", 0);
		ভঙ্গ;
	স্ৱভাৱ:
		debug_f("unhandled event %d", event);
		ভঙ্গ;
	}
}
#endif /* USE_LINUX_AUDIT */
