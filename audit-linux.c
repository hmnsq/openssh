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

#ಅನ್ತರ್ಭಾವ "includes.h"
#ಯದಿ defined(USE_LINUX_AUDIT)
#ಅನ್ತರ್ಭಾವ <libaudit.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>
#ಅನ್ತರ್ಭಾವ <string.h>

#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "audit.h"
#ಅನ್ತರ್ಭಾವ "canohost.h"
#ಅನ್ತರ್ಭಾವ "packet.h"

ಧ್ರುವ ವರ್ಣ *audit_username(ಶೂನ್ಯ);

ಪೂರ್ಣಾಙ್ಕ
linux_audit_record_event(ಪೂರ್ಣಾಙ್ಕ uid, ಧ್ರುವ ವರ್ಣ *username, ಧ್ರುವ ವರ್ಣ *hostname,
    ಧ್ರುವ ವರ್ಣ *ip, ಧ್ರುವ ವರ್ಣ *ttyn, ಪೂರ್ಣಾಙ್ಕ success)
{
	ಪೂರ್ಣಾಙ್ಕ audit_fd, rc, saved_errno;

	ಯದಿ ((audit_fd = audit_open()) < 0) {
		ಯದಿ (errno == EINVAL || errno == EPROTONOSUPPORT ||
		    errno == EAFNOSUPPORT)
			ಪ್ರತ್ಯಾಗಮ 1; /* No audit support in kernel */
		ಅನ್ಯಥಾ
			ಪ್ರತ್ಯಾಗಮ 0; /* Must prevent login */
	}
        ಯದಿ (hostname != ರಿಕ್ತ && strcmp(hostname, "UNKNOWN") == 0)
                hostname = ರಿಕ್ತ;
	rc = audit_log_acct_message(audit_fd, AUDIT_USER_LOGIN,
	    ರಿಕ್ತ, "login", username ? username : "(unknown)",
	    username == ರಿಕ್ತ ? uid : -1, hostname, ip, ttyn, success);
	saved_errno = errno;
	close(audit_fd);

	/*
	 * Do not report error if the error is EPERM and sshd is run as non
	 * root user.
	 */
	ಯದಿ ((rc == -EPERM) && (geteuid() != 0))
		rc = 0;
	errno = saved_errno;

	ಪ್ರತ್ಯಾಗಮ rc >= 0;
}

/* Below is the sshd audit API code */

ಶೂನ್ಯ
audit_connection_from(ಧ್ರುವ ವರ್ಣ *host, ಪೂರ್ಣಾಙ್ಕ port)
{
	/* not implemented */
}

ಶೂನ್ಯ
audit_run_command(ಧ್ರುವ ವರ್ಣ *command)
{
	/* not implemented */
}

ಶೂನ್ಯ
audit_session_open(ಸಂರಚನಾ logininfo *li)
{
	ಯದಿ (linux_audit_record_event(li->uid, ರಿಕ್ತ, li->hostname, ರಿಕ್ತ,
	    li->ಸಾಲು, 1) == 0)
		fatal("linux_audit_write_entry failed: %s", strerror(errno));
}

ಶೂನ್ಯ
audit_session_close(ಸಂರಚನಾ logininfo *li)
{
	/* not implemented */
}

ಶೂನ್ಯ
audit_event(ಸಂರಚನಾ ssh *ssh, ssh_audit_event_t event)
{
	ವಿಕಲ್ಪ(event) {
	ಪಕ್ಷ SSH_AUTH_SUCCESS:
	ಪಕ್ಷ SSH_CONNECTION_CLOSE:
	ಪಕ್ಷ SSH_NOLOGIN:
	ಪಕ್ಷ SSH_LOGIN_EXCEED_MAXTRIES:
	ಪಕ್ಷ SSH_LOGIN_ಬೇರು_DENIED:
		ಭಙ್ಗ;
	ಪಕ್ಷ SSH_AUTH_FAIL_NONE:
	ಪಕ್ಷ SSH_AUTH_FAIL_PASSWD:
	ಪಕ್ಷ SSH_AUTH_FAIL_KBDINT:
	ಪಕ್ಷ SSH_AUTH_FAIL_PUBKEY:
	ಪಕ್ಷ SSH_AUTH_FAIL_HOSTBASED:
	ಪಕ್ಷ SSH_AUTH_FAIL_GSSAPI:
	ಪಕ್ಷ SSH_INVALID_USER:
		linux_audit_record_event(-1, audit_username(), ರಿಕ್ತ,
		    ssh_remote_ipaddr(ssh), "sshd", 0);
		ಭಙ್ಗ;
	ಸ್ವಭಾವ:
		debug_f("unhandled event %d", event);
		ಭಙ್ಗ;
	}
}
#endif /* USE_LINUX_AUDIT */
