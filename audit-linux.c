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

#அந்தர்பாவ "includes.h"
#எனில் defined(USE_LINUX_AUDIT)
#அந்தர்பாவ <libaudit.h>
#அந்தர்பாவ <unistd.h>
#அந்தர்பாவ <string.h>

#அந்தர்பாவ "log.h"
#அந்தர்பாவ "audit.h"
#அந்தர்பாவ "canohost.h"
#அந்தர்பாவ "packet.h"

மாறிலி எழுத்து *audit_username(வெறுமை);

முழு
linux_audit_record_event(முழு uid, மாறிலி எழுத்து *username, மாறிலி எழுத்து *hostname,
    மாறிலி எழுத்து *ip, மாறிலி எழுத்து *ttyn, முழு success)
{
	முழு audit_fd, rc, saved_errno;

	எனில் ((audit_fd = audit_open()) < 0) {
		எனில் (errno == EINVAL || errno == EPROTONOSUPPORT ||
		    errno == EAFNOSUPPORT)
			திரும்பு 1; /* No audit support in kernel */
		இல்லையெனில்
			திரும்பு 0; /* Must prevent login */
	}
        எனில் (hostname != வெற்று && strcmp(hostname, "UNKNOWN") == 0)
                hostname = வெற்று;
	rc = audit_log_acct_message(audit_fd, AUDIT_USER_LOGIN,
	    வெற்று, "login", username ? username : "(unknown)",
	    username == வெற்று ? uid : -1, hostname, ip, ttyn, success);
	saved_errno = errno;
	close(audit_fd);

	/*
	 * Do not report error if the error is EPERM and sshd is run as non
	 * root user.
	 */
	எனில் ((rc == -EPERM) && (geteuid() != 0))
		rc = 0;
	errno = saved_errno;

	திரும்பு rc >= 0;
}

/* Below is the sshd audit API code */

வெறுமை
audit_connection_from(மாறிலி எழுத்து *host, முழு port)
{
	/* not implemented */
}

வெறுமை
audit_run_command(மாறிலி எழுத்து *command)
{
	/* not implemented */
}

வெறுமை
audit_session_open(கட்டமைப்பு logininfo *li)
{
	எனில் (linux_audit_record_event(li->uid, வெற்று, li->hostname, வெற்று,
	    li->வரி, 1) == 0)
		fatal("linux_audit_write_entry failed: %s", strerror(errno));
}

வெறுமை
audit_session_close(கட்டமைப்பு logininfo *li)
{
	/* not implemented */
}

வெறுமை
audit_event(கட்டமைப்பு ssh *ssh, ssh_audit_event_t event)
{
	தேர்வு(event) {
	நிலை SSH_AUTH_SUCCESS:
	நிலை SSH_CONNECTION_CLOSE:
	நிலை SSH_NOLOGIN:
	நிலை SSH_LOGIN_EXCEED_MAXTRIES:
	நிலை SSH_LOGIN_வேர்_DENIED:
		நிறுத்து;
	நிலை SSH_AUTH_FAIL_NONE:
	நிலை SSH_AUTH_FAIL_PASSWD:
	நிலை SSH_AUTH_FAIL_KBDINT:
	நிலை SSH_AUTH_FAIL_PUBKEY:
	நிலை SSH_AUTH_FAIL_HOSTBASED:
	நிலை SSH_AUTH_FAIL_GSSAPI:
	நிலை SSH_INVALID_USER:
		linux_audit_record_event(-1, audit_username(), வெற்று,
		    ssh_remote_ipaddr(ssh), "sshd", 0);
		நிறுத்து;
	இயல்பு:
		debug_f("unhandled event %d", event);
		நிறுத்து;
	}
}
#endif /* USE_LINUX_AUDIT */
