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

#અન્તર્ભાવ "includes.h"
#જો defined(USE_LINUX_AUDIT)
#અન્તર્ભાવ <libaudit.h>
#અન્તર્ભાવ <unistd.h>
#અન્તર્ભાવ <string.h>

#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "audit.h"
#અન્તર્ભાવ "canohost.h"
#અન્તર્ભાવ "packet.h"

અચલ અક્ષર *audit_username(શૂન્ય);

પૂર્ણાંક
linux_audit_record_event(પૂર્ણાંક uid, અચલ અક્ષર *username, અચલ અક્ષર *hostname,
    અચલ અક્ષર *ip, અચલ અક્ષર *ttyn, પૂર્ણાંક success)
{
	પૂર્ણાંક audit_fd, rc, saved_errno;

	જો ((audit_fd = audit_open()) < 0) {
		જો (errno == EINVAL || errno == EPROTONOSUPPORT ||
		    errno == EAFNOSUPPORT)
			પાછા 1; /* No audit support in kernel */
		નહીંતર
			પાછા 0; /* Must prevent login */
	}
        જો (hostname != ખાલી && strcmp(hostname, "UNKNOWN") == 0)
                hostname = ખાલી;
	rc = audit_log_acct_message(audit_fd, AUDIT_USER_LOGIN,
	    ખાલી, "login", username ? username : "(unknown)",
	    username == ખાલી ? uid : -1, hostname, ip, ttyn, success);
	saved_errno = errno;
	close(audit_fd);

	/*
	 * Do not report error if the error is EPERM and sshd is run as non
	 * root user.
	 */
	જો ((rc == -EPERM) && (geteuid() != 0))
		rc = 0;
	errno = saved_errno;

	પાછા rc >= 0;
}

/* Below is the sshd audit API code */

શૂન્ય
audit_connection_from(અચલ અક્ષર *host, પૂર્ણાંક port)
{
	/* not implemented */
}

શૂન્ય
audit_run_command(અચલ અક્ષર *command)
{
	/* not implemented */
}

શૂન્ય
audit_session_open(સંરચના logininfo *li)
{
	જો (linux_audit_record_event(li->uid, ખાલી, li->hostname, ખાલી,
	    li->લીટી, 1) == 0)
		fatal("linux_audit_write_entry failed: %s", strerror(errno));
}

શૂન્ય
audit_session_close(સંરચના logininfo *li)
{
	/* not implemented */
}

શૂન્ય
audit_event(સંરચના ssh *ssh, ssh_audit_event_t event)
{
	પસંદગી(event) {
	સ્થિતિ SSH_AUTH_SUCCESS:
	સ્થિતિ SSH_CONNECTION_CLOSE:
	સ્થિતિ SSH_NOLOGIN:
	સ્થિતિ SSH_LOGIN_EXCEED_MAXTRIES:
	સ્થિતિ SSH_LOGIN_મૂળ_DENIED:
		તોડો;
	સ્થિતિ SSH_AUTH_FAIL_NONE:
	સ્થિતિ SSH_AUTH_FAIL_PASSWD:
	સ્થિતિ SSH_AUTH_FAIL_KBDINT:
	સ્થિતિ SSH_AUTH_FAIL_PUBKEY:
	સ્થિતિ SSH_AUTH_FAIL_HOSTBASED:
	સ્થિતિ SSH_AUTH_FAIL_GSSAPI:
	સ્થિતિ SSH_INVALID_USER:
		linux_audit_record_event(-1, audit_username(), ખાલી,
		    ssh_remote_ipaddr(ssh), "sshd", 0);
		તોડો;
	મૂળભૂત:
		debug_f("unhandled event %d", event);
		તોડો;
	}
}
#endif /* USE_LINUX_AUDIT */
