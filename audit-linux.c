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

#అన్తర్భావ "includes.h"
#ఒకవేళ defined(USE_LINUX_AUDIT)
#అన్తర్భావ <libaudit.h>
#అన్తర్భావ <unistd.h>
#అన్తర్భావ <string.h>

#అన్తర్భావ "log.h"
#అన్తర్భావ "audit.h"
#అన్తర్భావ "canohost.h"
#అన్తర్భావ "packet.h"

స్థిరరాశి అక్షరం *audit_username(శూన్య);

పూర్ణాంకం
linux_audit_రికార్డు_event(పూర్ణాంకం uid, స్థిరరాశి అక్షరం *username, స్థిరరాశి అక్షరం *hostname,
    స్థిరరాశి అక్షరం *ip, స్థిరరాశి అక్షరం *ttyn, పూర్ణాంకం success)
{
	పూర్ణాంకం audit_fd, rc, saved_errno;

	ఒకవేళ ((audit_fd = audit_open()) < 0) {
		ఒకవేళ (errno == EINVAL || errno == EPROTONOSUPPORT ||
		    errno == EAFNOSUPPORT)
			తిరిగి 1; /* No audit support in kernel */
		లేకపోతే
			తిరిగి 0; /* Must prevent login */
	}
        ఒకవేళ (hostname != ఖాళీ && strcmp(hostname, "UNKNOWN") == 0)
                hostname = ఖాళీ;
	rc = audit_log_acct_సందేశం(audit_fd, AUDIT_USER_LOGIN,
	    ఖాళీ, "login", username ? username : "(unknown)",
	    username == ఖాళీ ? uid : -1, hostname, ip, ttyn, success);
	saved_errno = errno;
	close(audit_fd);

	/*
	 * Do not report error if the error is EPERM and sshd is run as non
	 * root user.
	 */
	ఒకవేళ ((rc == -EPERM) && (geteuid() != 0))
		rc = 0;
	errno = saved_errno;

	తిరిగి rc >= 0;
}

/* Below is the sshd audit API code */

శూన్య
audit_connection_from(స్థిరరాశి అక్షరం *host, పూర్ణాంకం పోర్టు)
{
	/* not implemented */
}

శూన్య
audit_నిరంతరం_command(స్థిరరాశి అక్షరం *command)
{
	/* not implemented */
}

శూన్య
audit_session_open(నిర్మాణం logininfo *li)
{
	ఒకవేళ (linux_audit_రికార్డు_event(li->uid, ఖాళీ, li->hostname, ఖాళీ,
	    li->పంక్తి, 1) == 0)
		fatal("linux_audit_write_entry failed: %s", strerror(errno));
}

శూన్య
audit_session_close(నిర్మాణం logininfo *li)
{
	/* not implemented */
}

శూన్య
audit_event(నిర్మాణం ssh *ssh, ssh_audit_event_t event)
{
	ఎంపిక(event) {
	స్థితి SSH_AUTH_SUCCESS:
	స్థితి SSH_CONNECTION_CLOSE:
	స్థితి SSH_NOLOGIN:
	స్థితి SSH_LOGIN_EXCEED_MAXTRIES:
	స్థితి SSH_LOGIN_మూలం_DENIED:
		ఆపు;
	స్థితి SSH_AUTH_FAIL_NONE:
	స్థితి SSH_AUTH_FAIL_PASSWD:
	స్థితి SSH_AUTH_FAIL_KBDINT:
	స్థితి SSH_AUTH_FAIL_PUBKEY:
	స్థితి SSH_AUTH_FAIL_HOSTBASED:
	స్థితి SSH_AUTH_FAIL_GSSAPI:
	స్థితి SSH_INVALID_USER:
		linux_audit_రికార్డు_event(-1, audit_username(), ఖాళీ,
		    ssh_remote_ipaddr(ssh), "sshd", 0);
		ఆపు;
	అప్రమేయ:
		debug_f("unhandled event %d", event);
		ఆపు;
	}
}
#అయితే_ముగింపు /* USE_LINUX_AUDIT */
