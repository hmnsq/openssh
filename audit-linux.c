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
#ಆದರೆ defined(USE_LINUX_AUDIT)
#ಅನ್ತರ್ಭಾವ <libaudit.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>
#ಅನ್ತರ್ಭಾವ <string.h>

#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "audit.h"
#ಅನ್ತರ್ಭಾವ "canohost.h"
#ಅನ್ತರ್ಭಾವ "packet.h"

ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *audit_username(ಶೂನ್ಯ);

ಪೂರ್ಣಾಂಕ
linux_audit_ದಾಖಲೆ_event(ಪೂರ್ಣಾಂಕ uid, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *username, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *hostname,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ip, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ttyn, ಪೂರ್ಣಾಂಕ success)
{
	ಪೂರ್ಣಾಂಕ audit_fd, rc, saved_errno;

	ಆದರೆ ((audit_fd = audit_open()) < 0) {
		ಆದರೆ (errno == EINVAL || errno == EPROTONOSUPPORT ||
		    errno == EAFNOSUPPORT)
			ಹಿಂತಿರುಗಿ 1; /* No audit support in kernel */
		ಇಲ್ಲದಿದ್ದರೆ
			ಹಿಂತಿರುಗಿ 0; /* Must prevent login */
	}
        ಆದರೆ (hostname != ಖಾಲಿ && strcmp(hostname, "UNKNOWN") == 0)
                hostname = ಖಾಲಿ;
	rc = audit_log_acct_ಸಂದೇಶ(audit_fd, AUDIT_USER_LOGIN,
	    ಖಾಲಿ, "login", username ? username : "(unknown)",
	    username == ಖಾಲಿ ? uid : -1, hostname, ip, ttyn, success);
	saved_errno = errno;
	close(audit_fd);

	/*
	 * Do not report error if the error is EPERM and sshd is run as non
	 * root user.
	 */
	ಆದರೆ ((rc == -EPERM) && (geteuid() != 0))
		rc = 0;
	errno = saved_errno;

	ಹಿಂತಿರುಗಿ rc >= 0;
}

/* Below is the sshd audit API code */

ಶೂನ್ಯ
audit_connection_from(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *host, ಪೂರ್ಣಾಂಕ ಪೋರ್ಟ್)
{
	/* not implemented */
}

ಶೂನ್ಯ
audit_ಸತತ_command(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *command)
{
	/* not implemented */
}

ಶೂನ್ಯ
audit_session_open(ರಚನೆ logininfo *li)
{
	ಆದರೆ (linux_audit_ದಾಖಲೆ_event(li->uid, ಖಾಲಿ, li->hostname, ಖಾಲಿ,
	    li->ಸಾಲು, 1) == 0)
		fatal("linux_audit_write_entry failed: %s", strerror(errno));
}

ಶೂನ್ಯ
audit_session_close(ರಚನೆ logininfo *li)
{
	/* not implemented */
}

ಶೂನ್ಯ
audit_event(ರಚನೆ ssh *ssh, ssh_audit_event_t event)
{
	ಆಯ್ಕೆ(event) {
	ಸ್ಥಿತಿ SSH_AUTH_SUCCESS:
	ಸ್ಥಿತಿ SSH_CONNECTION_CLOSE:
	ಸ್ಥಿತಿ SSH_NOLOGIN:
	ಸ್ಥಿತಿ SSH_LOGIN_EXCEED_MAXTRIES:
	ಸ್ಥಿತಿ SSH_LOGIN_ಬೇರು_DENIED:
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ SSH_AUTH_FAIL_NONE:
	ಸ್ಥಿತಿ SSH_AUTH_FAIL_PASSWD:
	ಸ್ಥಿತಿ SSH_AUTH_FAIL_KBDINT:
	ಸ್ಥಿತಿ SSH_AUTH_FAIL_PUBKEY:
	ಸ್ಥಿತಿ SSH_AUTH_FAIL_HOSTBASED:
	ಸ್ಥಿತಿ SSH_AUTH_FAIL_GSSAPI:
	ಸ್ಥಿತಿ SSH_INVALID_USER:
		linux_audit_ದಾಖಲೆ_event(-1, audit_username(), ಖಾಲಿ,
		    ssh_remote_ipaddr(ssh), "sshd", 0);
		ನಿಲ್ಲಿಸು;
	ಪೂರ್ವನಿಯೋಜಿತ:
		debug_f("unhandled event %d", event);
		ನಿಲ್ಲಿಸು;
	}
}
#ಆದರೆ_ಅಂತ್ಯ /* USE_LINUX_AUDIT */
