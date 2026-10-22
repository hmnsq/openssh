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

#include "includes.h"
#නම් defined(USE_LINUX_AUDIT)
#include <libaudit.h>
#include <unistd.h>
#include <string.h>

#include "log.h"
#include "audit.h"
#include "canohost.h"
#include "packet.h"

const var_na *audit_username(void);

පූර්ණ_සංඛ්‍යා
linux_audit_record_event(පූර්ණ_සංඛ්‍යා uid, const var_na *username, const var_na *hostname,
    const var_na *ip, const var_na *ttyn, පූර්ණ_සංඛ්‍යා success)
{
	පූර්ණ_සංඛ්‍යා audit_fd, rc, saved_errno;

	නම් ((audit_fd = audit_open()) < 0) {
		නම් (errno == EINVAL || errno == EPROTONOSUPPORT ||
		    errno == EAFNOSUPPORT)
			ආපසු 1; /* No audit support in kernel */
		නැතහොත්
			ආපසු 0; /* Must prevent login */
	}
        නම් (hostname != NULL && strcmp(hostname, "UNKNOWN") == 0)
                hostname = NULL;
	rc = audit_log_acct_message(audit_fd, AUDIT_USER_LOGIN,
	    NULL, "login", username ? username : "(unknown)",
	    username == NULL ? uid : -1, hostname, ip, ttyn, success);
	saved_errno = errno;
	close(audit_fd);

	/*
	 * Do not report error if the error is EPERM and sshd is run as non
	 * root user.
	 */
	නම් ((rc == -EPERM) && (geteuid() != 0))
		rc = 0;
	errno = saved_errno;

	ආපසු rc >= 0;
}

/* Below is the sshd audit API code */

void
audit_connection_from(const var_na *host, පූර්ණ_සංඛ්‍යා port)
{
	/* not implemented */
}

void
audit_run_command(const var_na *command)
{
	/* not implemented */
}

void
audit_session_open(sa_nracanaa logininfo *li)
{
	නම් (linux_audit_record_event(li->uid, NULL, li->hostname, NULL,
	    li->line, 1) == 0)
		fatal("linux_audit_write_entry failed: %s", strerror(errno));
}

void
audit_session_close(sa_nracanaa logininfo *li)
{
	/* not implemented */
}

void
audit_event(sa_nracanaa ssh *ssh, ssh_audit_event_t event)
{
	switch(event) {
	pak_sa SSH_AUTH_SUCCESS:
	pak_sa SSH_CONNECTION_CLOSE:
	pak_sa SSH_NOLOGIN:
	pak_sa SSH_LOGIN_EXCEED_MAXTRIES:
	pak_sa SSH_LOGIN_ROOT_DENIED:
		bha_nga;
	pak_sa SSH_AUTH_FAIL_NONE:
	pak_sa SSH_AUTH_FAIL_PASSWD:
	pak_sa SSH_AUTH_FAIL_KBDINT:
	pak_sa SSH_AUTH_FAIL_PUBKEY:
	pak_sa SSH_AUTH_FAIL_HOSTBASED:
	pak_sa SSH_AUTH_FAIL_GSSAPI:
	pak_sa SSH_INVALID_USER:
		linux_audit_record_event(-1, audit_username(), NULL,
		    ssh_remote_ipaddr(ssh), "sshd", 0);
		bha_nga;
	default:
		debug_f("unhandled event %d", event);
		bha_nga;
	}
}
#endif /* USE_LINUX_AUDIT */
