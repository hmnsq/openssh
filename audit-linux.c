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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"
#ਜੇ defined(USE_LINUX_AUDIT)
#ਅਨ੍ਤਰ੍ਭਾਵ <libaudit.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "audit.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "canohost.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "packet.h"

ਅਚਲ ਅੱਖਰ *audit_username(ਖਾਲੀ);

ਪੂਰਨ
linux_audit_ਰਿਕਾਰਡ_event(ਪੂਰਨ uid, ਅਚਲ ਅੱਖਰ *username, ਅਚਲ ਅੱਖਰ *hostname,
    ਅਚਲ ਅੱਖਰ *ip, ਅਚਲ ਅੱਖਰ *ttyn, ਪੂਰਨ success)
{
	ਪੂਰਨ audit_fd, rc, saved_errno;

	ਜੇ ((audit_fd = audit_open()) < 0) {
		ਜੇ (errno == EINVAL || errno == EPROTONOSUPPORT ||
		    errno == EAFNOSUPPORT)
			ਵਾਪਸ 1; /* No audit support in kernel */
		ਨਹੀਂਤਾਂ
			ਵਾਪਸ 0; /* Must prevent login */
	}
        ਜੇ (hostname != ਨਿਰਾ && strcmp(hostname, "UNKNOWN") == 0)
                hostname = ਨਿਰਾ;
	rc = audit_log_acct_ਸੁਨੇਹਾ(audit_fd, AUDIT_USER_LOGIN,
	    ਨਿਰਾ, "login", username ? username : "(unknown)",
	    username == ਨਿਰਾ ? uid : -1, hostname, ip, ttyn, success);
	saved_errno = errno;
	close(audit_fd);

	/*
	 * Do not report error if the error is EPERM and sshd is run as non
	 * root user.
	 */
	ਜੇ ((rc == -EPERM) && (geteuid() != 0))
		rc = 0;
	errno = saved_errno;

	ਵਾਪਸ rc >= 0;
}

/* Below is the sshd audit API code */

ਖਾਲੀ
audit_connection_from(ਅਚਲ ਅੱਖਰ *host, ਪੂਰਨ ਪੋਰਟ)
{
	/* not implemented */
}

ਖਾਲੀ
audit_ਲੜੀਵਾਰ_command(ਅਚਲ ਅੱਖਰ *command)
{
	/* not implemented */
}

ਖਾਲੀ
audit_session_open(ਬਣਤਰ logininfo *li)
{
	ਜੇ (linux_audit_ਰਿਕਾਰਡ_event(li->uid, ਨਿਰਾ, li->hostname, ਨਿਰਾ,
	    li->ਸਤਰ, 1) == 0)
		fatal("linux_audit_write_entry failed: %s", strerror(errno));
}

ਖਾਲੀ
audit_session_close(ਬਣਤਰ logininfo *li)
{
	/* not implemented */
}

ਖਾਲੀ
audit_event(ਬਣਤਰ ssh *ssh, ssh_audit_event_t event)
{
	ਚੋਣ(event) {
	ਹਾਲਤ SSH_AUTH_SUCCESS:
	ਹਾਲਤ SSH_CONNECTION_CLOSE:
	ਹਾਲਤ SSH_NOLOGIN:
	ਹਾਲਤ SSH_LOGIN_EXCEED_MAXTRIES:
	ਹਾਲਤ SSH_LOGIN_ਜੜ੍ਹ_DENIED:
		ਰੋਕੋ;
	ਹਾਲਤ SSH_AUTH_FAIL_NONE:
	ਹਾਲਤ SSH_AUTH_FAIL_PASSWD:
	ਹਾਲਤ SSH_AUTH_FAIL_KBDINT:
	ਹਾਲਤ SSH_AUTH_FAIL_PUBKEY:
	ਹਾਲਤ SSH_AUTH_FAIL_HOSTBASED:
	ਹਾਲਤ SSH_AUTH_FAIL_GSSAPI:
	ਹਾਲਤ SSH_INVALID_USER:
		linux_audit_ਰਿਕਾਰਡ_event(-1, audit_username(), ਨਿਰਾ,
		    ssh_remote_ipaddr(ssh), "sshd", 0);
		ਰੋਕੋ;
	ਮੂਲ:
		debug_f("unhandled event %d", event);
		ਰੋਕੋ;
	}
}
#ਜੇ_ਅੰਤ /* USE_LINUX_AUDIT */
