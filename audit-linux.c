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

#അന്തര്ഭാവ "includes.h"
#എങ്കിൽ defined(USE_LINUX_AUDIT)
#അന്തര്ഭാവ <libaudit.h>
#അന്തര്ഭാവ <unistd.h>
#അന്തര്ഭാവ <string.h>

#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "audit.h"
#അന്തര്ഭാവ "canohost.h"
#അന്തര്ഭാവ "packet.h"

സ്ഥിരം അക്ഷരം *audit_username(ശൂന്യം);

പൂർണ്ണസംഖ്യ
linux_audit_record_event(പൂർണ്ണസംഖ്യ uid, സ്ഥിരം അക്ഷരം *username, സ്ഥിരം അക്ഷരം *hostname,
    സ്ഥിരം അക്ഷരം *ip, സ്ഥിരം അക്ഷരം *ttyn, പൂർണ്ണസംഖ്യ success)
{
	പൂർണ്ണസംഖ്യ audit_fd, rc, saved_errno;

	എങ്കിൽ ((audit_fd = audit_open()) < 0) {
		എങ്കിൽ (errno == EINVAL || errno == EPROTONOSUPPORT ||
		    errno == EAFNOSUPPORT)
			തിരികെ 1; /* No audit support in kernel */
		അല്ലെങ്കിൽ
			തിരികെ 0; /* Must prevent login */
	}
        എങ്കിൽ (hostname != ശൂന്യ && strcmp(hostname, "UNKNOWN") == 0)
                hostname = ശൂന്യ;
	rc = audit_log_acct_message(audit_fd, AUDIT_USER_LOGIN,
	    ശൂന്യ, "login", username ? username : "(unknown)",
	    username == ശൂന്യ ? uid : -1, hostname, ip, ttyn, success);
	saved_errno = errno;
	close(audit_fd);

	/*
	 * Do not report error if the error is EPERM and sshd is run as non
	 * root user.
	 */
	എങ്കിൽ ((rc == -EPERM) && (geteuid() != 0))
		rc = 0;
	errno = saved_errno;

	തിരികെ rc >= 0;
}

/* Below is the sshd audit API code */

ശൂന്യം
audit_connection_from(സ്ഥിരം അക്ഷരം *host, പൂർണ്ണസംഖ്യ port)
{
	/* not implemented */
}

ശൂന്യം
audit_run_command(സ്ഥിരം അക്ഷരം *command)
{
	/* not implemented */
}

ശൂന്യം
audit_session_open(ഘടന logininfo *li)
{
	എങ്കിൽ (linux_audit_record_event(li->uid, ശൂന്യ, li->hostname, ശൂന്യ,
	    li->വരി, 1) == 0)
		fatal("linux_audit_write_entry failed: %s", strerror(errno));
}

ശൂന്യം
audit_session_close(ഘടന logininfo *li)
{
	/* not implemented */
}

ശൂന്യം
audit_event(ഘടന ssh *ssh, ssh_audit_event_t event)
{
	തിരഞ്ഞെടുപ്പ്(event) {
	അവസ്ഥ SSH_AUTH_SUCCESS:
	അവസ്ഥ SSH_CONNECTION_CLOSE:
	അവസ്ഥ SSH_NOLOGIN:
	അവസ്ഥ SSH_LOGIN_EXCEED_MAXTRIES:
	അവസ്ഥ SSH_LOGIN_വേര്_DENIED:
		നിർത്തുക;
	അവസ്ഥ SSH_AUTH_FAIL_NONE:
	അവസ്ഥ SSH_AUTH_FAIL_PASSWD:
	അവസ്ഥ SSH_AUTH_FAIL_KBDINT:
	അവസ്ഥ SSH_AUTH_FAIL_PUBKEY:
	അവസ്ഥ SSH_AUTH_FAIL_HOSTBASED:
	അവസ്ഥ SSH_AUTH_FAIL_GSSAPI:
	അവസ്ഥ SSH_INVALID_USER:
		linux_audit_record_event(-1, audit_username(), ശൂന്യ,
		    ssh_remote_ipaddr(ssh), "sshd", 0);
		നിർത്തുക;
	സ്ഥിരസ്ഥിതി:
		debug_f("unhandled event %d", event);
		നിർത്തുക;
	}
}
#endif /* USE_LINUX_AUDIT */
