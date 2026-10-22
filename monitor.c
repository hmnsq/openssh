/* $OpenBSD: monitor.c,v 1.260 2026/10/11 20:41:20 dtucker Exp $ */
/*
 * Copyright 2002 Niels Provos <provos@citi.umich.edu>
 * Copyright 2002 Markus Friedl <markus@openbsd.org>
 * All rights reserved.
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
 */

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <sys/wait.h>
#অন্তর্ভাব <sys/socket.h>
#অন্তর্ভাব <sys/tree.h>
#অন্তর্ভাব <sys/queue.h>

#অন্তর্ভাব <errno.h>
#অন্তর্ভাব <fcntl.h>
#অন্তর্ভাব <limits.h>
#অন্তর্ভাব <paths.h>
#অন্তর্ভাব <poll.h>
#অন্তর্ভাব <pwd.h>
#অন্তর্ভাব <signal.h>
#অন্তর্ভাব <stdarg.h>
#অন্তর্ভাব <stdint.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <unistd.h>

#ifdef WITH_OPENSSL
#অন্তর্ভাব <openssl/dh.h>
#endif

#অন্তর্ভাব "openbsd-compat/openssl-compat.h"

#অন্তর্ভাব "atomicio.h"
#অন্তর্ভাব "xmalloc.h"
#অন্তর্ভাব "ssh.h"
#অন্তর্ভাব "sshkey.h"
#অন্তর্ভাব "sshbuf.h"
#অন্তর্ভাব "hostfile.h"
#অন্তর্ভাব "auth.h"
#অন্তর্ভাব "cipher.h"
#অন্তর্ভাব "kex.h"
#অন্তর্ভাব "dh.h"
#অন্তর্ভাব "auth-pam.h"
#অন্তর্ভাব "packet.h"
#অন্তর্ভাব "auth-options.h"
#অন্তর্ভাব "sshpty.h"
#অন্তর্ভাব "channels.h"
#অন্তর্ভাব "session.h"
#অন্তর্ভাব "sshlogin.h"
#অন্তর্ভাব "canohost.h"
#অন্তর্ভাব "log.h"
#অন্তর্ভাব "misc.h"
#অন্তর্ভাব "servconf.h"
#অন্তর্ভাব "monitor.h"
#ifdef GSSAPI
#অন্তর্ভাব "ssh-gss.h"
#endif
#অন্তর্ভাব "monitor_wrap.h"
#অন্তর্ভাব "monitor_fdpass.h"
#অন্তর্ভাব "compat.h"
#অন্তর্ভাব "ssh2.h"
#অন্তর্ভাব "authfd.h"
#অন্তর্ভাব "match.h"
#অন্তর্ভাব "ssherr.h"
#অন্তর্ভাব "sk-api.h"
#অন্তর্ভাব "srclimit.h"

#ifdef GSSAPI
স্থির Gssctxt *gsscontext = ফাঁকা;
#endif

/* Imports */
বাহ্যিক ServerOptions options;
বাহ্যিক u_int utmp_len;
বাহ্যিক কাঠামো sshbuf *cfg;
বাহ্যিক কাঠামো sshbuf *loginmsg;
বাহ্যিক কাঠামো include_list includes;
বাহ্যিক কাঠামো sshauthopt *auth_opts; /* XXX move to permanent ssh->authctxt? */

/* State exported from the child */
স্থির কাঠামো sshbuf *child_state;

/* Functions on the monitor that answer unprivileged requests */

পূর্ণসংখ্যা mm_answer_moduli(কাঠামো ssh *, পূর্ণসংখ্যা, কাঠামো sshbuf *);
পূর্ণসংখ্যা mm_answer_setcompat(কাঠামো ssh *, পূর্ণসংখ্যা, কাঠামো sshbuf *);
পূর্ণসংখ্যা mm_answer_sign(কাঠামো ssh *, পূর্ণসংখ্যা, কাঠামো sshbuf *);
পূর্ণসংখ্যা mm_answer_pwnamallow(কাঠামো ssh *, পূর্ণসংখ্যা, কাঠামো sshbuf *);
পূর্ণসংখ্যা mm_answer_auth2_read_banner(কাঠামো ssh *, পূর্ণসংখ্যা, কাঠামো sshbuf *);
পূর্ণসংখ্যা mm_answer_authserv(কাঠামো ssh *, পূর্ণসংখ্যা, কাঠামো sshbuf *);
পূর্ণসংখ্যা mm_answer_authpassword(কাঠামো ssh *, পূর্ণসংখ্যা, কাঠামো sshbuf *);
পূর্ণসংখ্যা mm_answer_bsdauthquery(কাঠামো ssh *, পূর্ণসংখ্যা, কাঠামো sshbuf *);
পূর্ণসংখ্যা mm_answer_bsdauthrespond(কাঠামো ssh *, পূর্ণসংখ্যা, কাঠামো sshbuf *);
পূর্ণসংখ্যা mm_answer_keyallowed(কাঠামো ssh *, পূর্ণসংখ্যা, কাঠামো sshbuf *);
পূর্ণসংখ্যা mm_answer_keyverify(কাঠামো ssh *, পূর্ণসংখ্যা, কাঠামো sshbuf *);
পূর্ণসংখ্যা mm_answer_pty(কাঠামো ssh *, পূর্ণসংখ্যা, কাঠামো sshbuf *);
পূর্ণসংখ্যা mm_answer_pty_cleanup(কাঠামো ssh *, পূর্ণসংখ্যা, কাঠামো sshbuf *);
পূর্ণসংখ্যা mm_answer_term(কাঠামো ssh *, পূর্ণসংখ্যা, কাঠামো sshbuf *);
পূর্ণসংখ্যা mm_answer_state(কাঠামো ssh *, পূর্ণসংখ্যা, কাঠামো sshbuf *);

#ifdef USE_PAM
পূর্ণসংখ্যা mm_answer_pam_start(কাঠামো ssh *, পূর্ণসংখ্যা, কাঠামো sshbuf *);
পূর্ণসংখ্যা mm_answer_pam_account(কাঠামো ssh *, পূর্ণসংখ্যা, কাঠামো sshbuf *);
পূর্ণসংখ্যা mm_answer_pam_init_ctx(কাঠামো ssh *, পূর্ণসংখ্যা, কাঠামো sshbuf *);
পূর্ণসংখ্যা mm_answer_pam_query(কাঠামো ssh *, পূর্ণসংখ্যা, কাঠামো sshbuf *);
পূর্ণসংখ্যা mm_answer_pam_respond(কাঠামো ssh *, পূর্ণসংখ্যা, কাঠামো sshbuf *);
পূর্ণসংখ্যা mm_answer_pam_free_ctx(কাঠামো ssh *, পূর্ণসংখ্যা, কাঠামো sshbuf *);
#endif

#ifdef GSSAPI
পূর্ণসংখ্যা mm_answer_gss_setup_ctx(কাঠামো ssh *, পূর্ণসংখ্যা, কাঠামো sshbuf *);
পূর্ণসংখ্যা mm_answer_gss_accept_ctx(কাঠামো ssh *, পূর্ণসংখ্যা, কাঠামো sshbuf *);
পূর্ণসংখ্যা mm_answer_gss_userok(কাঠামো ssh *, পূর্ণসংখ্যা, কাঠামো sshbuf *);
পূর্ণসংখ্যা mm_answer_gss_checkmic(কাঠামো ssh *, পূর্ণসংখ্যা, কাঠামো sshbuf *);
#endif

#ifdef SSH_AUDIT_EVENTS
পূর্ণসংখ্যা mm_answer_audit_event(কাঠামো ssh *, পূর্ণসংখ্যা, কাঠামো sshbuf *);
পূর্ণসংখ্যা mm_answer_audit_command(কাঠামো ssh *, পূর্ণসংখ্যা, কাঠামো sshbuf *);
#endif

স্থির Authctxt *authctxt;

/* local state for key verify */
স্থির u_char *চাবি_blob = ফাঁকা;
স্থির আকার_t চাবি_bloblen = 0;
স্থির u_int চাবি_blobtype = MM_NOKEY;
স্থির কাঠামো sshauthopt *চাবি_opts = ফাঁকা;
স্থির অক্ষর *hostbased_cuser = ফাঁকা;
স্থির অক্ষর *hostbased_chost = ফাঁকা;
স্থির অক্ষর *auth_method = "unknown";
স্থির অক্ষর *auth_submethod = ফাঁকা;
স্থির u_int session_id2_len = 0;
স্থির u_char *session_id2 = ফাঁকা;
স্থির pid_t monitor_child_pid;
স্থির পূর্ণসংখ্যা auth_attempted = 0;
স্থির পূর্ণসংখ্যা invalid_user = 0;
স্থির পূর্ণসংখ্যা compat_set = 0;

কাঠামো mon_table {
	গণনা monitor_reqtype type;
	পূর্ণসংখ্যা flags;
	পূর্ণসংখ্যা (*f)(কাঠামো ssh *, পূর্ণসংখ্যা, কাঠামো sshbuf *);
};

#define MON_ISAUTH	0x0004	/* Required for Authentication */
#define MON_AUTHDECIDE	0x0008	/* Decides Authentication */
#define MON_ONCE	0x0010	/* Disable after calling */
#define MON_ALOG	0x0020	/* Log auth attempt without authenticating */

#define MON_AUTH	(MON_ISAUTH|MON_AUTHDECIDE)

#define MON_PERMIT	0x1000	/* Request is permitted */

স্থির পূর্ণসংখ্যা monitor_read(কাঠামো ssh *, কাঠামো monitor *, কাঠামো mon_table *,
    কাঠামো mon_table **);
স্থির পূর্ণসংখ্যা monitor_read_log(কাঠামো monitor *);

কাঠামো mon_table mon_dispatch_proto20[] = {
    {MONITOR_REQ_STATE, MON_ONCE, mm_answer_state},
#ifdef WITH_OPENSSL
    {MONITOR_REQ_MODULI, MON_ONCE, mm_answer_moduli},
#endif
    {MONITOR_REQ_SETCOMPAT, MON_ONCE, mm_answer_setcompat},
    {MONITOR_REQ_SIGN, MON_ONCE, mm_answer_sign},
    {MONITOR_REQ_PWNAM, MON_ONCE, mm_answer_pwnamallow},
    {MONITOR_REQ_AUTHSERV, MON_ONCE, mm_answer_authserv},
    {MONITOR_REQ_AUTH2_READ_BANNER, MON_ONCE, mm_answer_auth2_read_banner},
    {MONITOR_REQ_AUTHPASSWORD, MON_AUTH, mm_answer_authpassword},
#ifdef USE_PAM
    {MONITOR_REQ_PAM_START, MON_ONCE, mm_answer_pam_start},
    {MONITOR_REQ_PAM_ACCOUNT, 0, mm_answer_pam_account},
    {MONITOR_REQ_PAM_INIT_CTX, MON_ONCE, mm_answer_pam_init_ctx},
    {MONITOR_REQ_PAM_QUERY, 0, mm_answer_pam_query},
    {MONITOR_REQ_PAM_RESPOND, MON_ONCE, mm_answer_pam_respond},
    {MONITOR_REQ_PAM_FREE_CTX, MON_ONCE|MON_AUTHDECIDE, mm_answer_pam_free_ctx},
#endif
#ifdef SSH_AUDIT_EVENTS
    {MONITOR_REQ_AUDIT_EVENT, MON_PERMIT, mm_answer_audit_event},
#endif
#ifdef BSD_AUTH
    {MONITOR_REQ_BSDAUTHQUERY, MON_ISAUTH, mm_answer_bsdauthquery},
    {MONITOR_REQ_BSDAUTHRESPOND, MON_AUTH, mm_answer_bsdauthrespond},
#endif
    {MONITOR_REQ_KEYALLOWED, MON_ISAUTH, mm_answer_keyallowed},
    {MONITOR_REQ_KEYVERIFY, MON_AUTH, mm_answer_keyverify},
#ifdef GSSAPI
    {MONITOR_REQ_GSSSETUP, MON_ISAUTH, mm_answer_gss_setup_ctx},
    {MONITOR_REQ_GSSSTEP, 0, mm_answer_gss_accept_ctx},
    {MONITOR_REQ_GSSUSEROK, MON_ONCE|MON_AUTHDECIDE, mm_answer_gss_userok},
    {MONITOR_REQ_GSSCHECKMIC, MON_ONCE, mm_answer_gss_checkmic},
#endif
    {0, 0, ফাঁকা}
};

কাঠামো mon_table mon_dispatch_postauth20[] = {
    {MONITOR_REQ_STATE, MON_ONCE, mm_answer_state},
#ifdef WITH_OPENSSL
    {MONITOR_REQ_MODULI, 0, mm_answer_moduli},
#endif
    {MONITOR_REQ_SIGN, 0, mm_answer_sign},
    {MONITOR_REQ_PTY, 0, mm_answer_pty},
    {MONITOR_REQ_PTYCLEANUP, 0, mm_answer_pty_cleanup},
    {MONITOR_REQ_TERM, 0, mm_answer_term},
#ifdef SSH_AUDIT_EVENTS
    {MONITOR_REQ_AUDIT_EVENT, MON_PERMIT, mm_answer_audit_event},
    {MONITOR_REQ_AUDIT_COMMAND, MON_PERMIT, mm_answer_audit_command},
#endif
    {0, 0, ফাঁকা}
};

কাঠামো mon_table *mon_dispatch;

/* Specifies if a certain message is allowed at the moment */
স্থির শূন্য
monitor_permit(কাঠামো mon_table *ent, গণনা monitor_reqtype type, পূর্ণসংখ্যা permit)
{
	যখন (ent->f != ফাঁকা) {
		যদি (ent->type == type) {
			ent->flags &= ~MON_PERMIT;
			ent->flags |= permit ? MON_PERMIT : 0;
			ফেরত;
		}
		ent++;
	}
}

স্থির শূন্য
monitor_permit_authentications(পূর্ণসংখ্যা permit)
{
	কাঠামো mon_table *ent = mon_dispatch;

	যখন (ent->f != ফাঁকা) {
		যদি (ent->flags & MON_AUTH) {
			ent->flags &= ~MON_PERMIT;
			ent->flags |= permit ? MON_PERMIT : 0;
		}
		ent++;
	}
}

শূন্য
monitor_child_preauth(কাঠামো ssh *ssh, কাঠামো monitor *pmonitor)
{
	কাঠামো mon_table *ent;
	পূর্ণসংখ্যা status, authenticated = 0, partial = 0;

	debug3("preauth child monitor started");

	যদি (pmonitor->m_recvfd >= 0)
		close(pmonitor->m_recvfd);
	যদি (pmonitor->m_log_sendfd >= 0)
		close(pmonitor->m_log_sendfd);
	pmonitor->m_log_sendfd = pmonitor->m_recvfd = -1;

	authctxt = (Authctxt *)ssh->authctxt;
	memset(authctxt, 0, আকার(*authctxt));
	ssh->authctxt = authctxt;

	authctxt->loginmsg = loginmsg;

	mon_dispatch = mon_dispatch_proto20;
	/* Permit requests for state, moduli and signatures */
	monitor_permit(mon_dispatch, MONITOR_REQ_STATE, 1);
	monitor_permit(mon_dispatch, MONITOR_REQ_MODULI, 1);
	monitor_permit(mon_dispatch, MONITOR_REQ_SETCOMPAT, 1);
	monitor_permit(mon_dispatch, MONITOR_REQ_SIGN, 1);

	/* The first few requests do not require asynchronous access */
	যখন (!authenticated) {
		partial = 0;
		auth_method = "unknown";
		auth_submethod = ফাঁকা;
		auth2_authctxt_reset_info(authctxt);

		authenticated = (monitor_read(ssh, pmonitor,
		    mon_dispatch, &ent) == 1);

		/* Record that auth was attempted to set exit status later */
		যদি ((ent->flags & MON_AUTH) != 0)
			auth_attempted = 1;

		/* Special handling for multiple required authentications */
		যদি (options.অঙ্ক_auth_methods != 0) {
			যদি (authenticated &&
			    !auth2_update_methods_lists(authctxt,
			    auth_method, auth_submethod)) {
				debug3_f("method %s: partial", auth_method);
				authenticated = 0;
				partial = 1;
			}
		}

		যদি (authenticated) {
			যদি (!(ent->flags & MON_AUTHDECIDE))
				fatal_f("unexpected authentication from %d",
				    ent->type);
			যদি (authctxt->pw->pw_uid == 0 &&
			    !auth_মূল_allowed(ssh, auth_method))
				authenticated = 0;
#ifdef USE_PAM
			/* PAM needs to perform account checks after auth */
			যদি (options.use_pam && authenticated) {
				কাঠামো sshbuf *m;

				যদি ((m = sshbuf_new()) == ফাঁকা)
					fatal("%s: sshbuf_new failed",
					    __func__);
				mm_request_receive_expect(pmonitor->m_sendfd,
				    MONITOR_REQ_PAM_ACCOUNT, m);
				authenticated = mm_answer_pam_account(
				    ssh, pmonitor->m_sendfd, m);
				sshbuf_free(m);
			}
#endif
		}
		যদি (ent->flags & (MON_AUTHDECIDE|MON_ALOG)) {
			auth_log(ssh, authenticated, partial,
			    auth_method, auth_submethod);
			যদি (!partial && !authenticated)
				authctxt->failures++;
			যদি (authenticated || partial) {
				auth2_update_session_info(authctxt,
				    auth_method, auth_submethod);
			}
		}
		যদি (authctxt->failures > options.max_authtries) {
			/* Shouldn't happen */
			fatal_f("privsep child made too many authentication "
			    "attempts");
		}
	}

	যদি (!authctxt->valid)
		fatal_f("authenticated invalid user");
	যদি (strcmp(auth_method, "unknown") == 0)
		fatal_f("authentication method name unknown");

	debug_f("user %s authenticated by privileged process", authctxt->user);
	auth_attempted = 0;
	ssh->authctxt = ফাঁকা;
	ssh_packet_set_log_preamble(ssh, "user %s", authctxt->user);

	mm_get_keystate(ssh, pmonitor);

	/* Drain any buffered messages from the child */
	যখন (pmonitor->m_log_recvfd != -1 && monitor_read_log(pmonitor) == 0)
		;

	/* Wait for the child's exit status */
	যখন (waitpid(pmonitor->m_pid, &status, 0) == -1) {
		যদি (errno == EINTR)
			চালু;
		fatal_f("waitpid: %s", strerror(errno));
	}
	যদি (WIFEXITED(status)) {
		যদি (WEXITSTATUS(status) != 0)
			fatal_f("preauth child %ld exited with status %d",
			    (long)pmonitor->m_pid, WEXITSTATUS(status));
	} অন্যথা যদি (WIFSIGNALED(status)) {
		fatal_f("preauth child %ld terminated by signal %d",
		    (long)pmonitor->m_pid, WTERMSIG(status));
	}
	debug3_f("preauth child %ld terminated successfully",
	    (long)pmonitor->m_pid);

	যদি (pmonitor->m_recvfd >= 0)
		close(pmonitor->m_recvfd);
	যদি (pmonitor->m_log_sendfd >= 0)
		close(pmonitor->m_log_sendfd);
	pmonitor->m_sendfd = pmonitor->m_log_recvfd = -1;
	pmonitor->m_pid = -1;
}

স্থির শূন্য
monitor_set_child_handler(pid_t pid)
{
	monitor_child_pid = pid;
}

স্থির শূন্য
monitor_child_handler(পূর্ণসংখ্যা sig)
{
	kill(monitor_child_pid, sig);
}

শূন্য
monitor_child_postauth(কাঠামো ssh *ssh, কাঠামো monitor *pmonitor)
{
	close(pmonitor->m_recvfd);
	pmonitor->m_recvfd = -1;

	monitor_set_child_handler(pmonitor->m_pid);
	ssh_signal(SIGHUP, &monitor_child_handler);
	ssh_signal(SIGTERM, &monitor_child_handler);
	ssh_signal(SIGINT, &monitor_child_handler);
#ifdef SIGXFSZ
	ssh_signal(SIGXFSZ, SIG_IGN);
#endif

	mon_dispatch = mon_dispatch_postauth20;

	/* Permit requests for moduli and signatures */
	monitor_permit(mon_dispatch, MONITOR_REQ_STATE, 1);
	monitor_permit(mon_dispatch, MONITOR_REQ_MODULI, 1);
	monitor_permit(mon_dispatch, MONITOR_REQ_SIGN, 1);
	monitor_permit(mon_dispatch, MONITOR_REQ_TERM, 1);

	যদি (auth_opts->permit_pty_flag) {
		monitor_permit(mon_dispatch, MONITOR_REQ_PTY, 1);
		monitor_permit(mon_dispatch, MONITOR_REQ_PTYCLEANUP, 1);
	}

	জন্য (;;)
		monitor_read(ssh, pmonitor, mon_dispatch, ফাঁকা);
}

স্থির পূর্ণসংখ্যা
monitor_read_log(কাঠামো monitor *pmonitor)
{
	কাঠামো sshbuf *logmsg;
	u_int len, level, forced;
	অক্ষর *বার্তা;
	u_char *p;
	পূর্ণসংখ্যা r;

	যদি ((logmsg = sshbuf_new()) == ফাঁকা)
		fatal_f("sshbuf_new");

	/* Read length */
	যদি ((r = sshbuf_reserve(logmsg, 4, &p)) != 0)
		fatal_fr(r, "reserve len");
	যদি (atomicio(পঠ, pmonitor->m_log_recvfd, p, 4) != 4) {
		যদি (errno == EPIPE) {
			sshbuf_free(logmsg);
			debug_f("child log fd closed");
			close(pmonitor->m_log_recvfd);
			pmonitor->m_log_recvfd = -1;
			ফেরত -1;
		}
		fatal_f("log fd read: %s", strerror(errno));
	}
	যদি ((r = sshbuf_get_u32(logmsg, &len)) != 0)
		fatal_fr(r, "parse len");
	যদি (len <= 4 || len > 8192)
		fatal_f("invalid log message length %u", len);

	/* Read severity, message */
	sshbuf_reset(logmsg);
	যদি ((r = sshbuf_reserve(logmsg, len, &p)) != 0)
		fatal_fr(r, "reserve msg");
	যদি (atomicio(পঠ, pmonitor->m_log_recvfd, p, len) != len)
		fatal_f("log fd read: %s", strerror(errno));
	যদি ((r = sshbuf_get_u32(logmsg, &level)) != 0 ||
	    (r = sshbuf_get_u32(logmsg, &forced)) != 0 ||
	    (r = sshbuf_get_cstring(logmsg, &বার্তা, ফাঁকা)) != 0)
		fatal_fr(r, "parse");

	/* Log it */
	যদি (log_level_name(level) == ফাঁকা)
		fatal_f("invalid log level %u (corrupted message?)", level);
	sshlogdirect(level, forced, "%s [%s]", বার্তা,
	    mon_dispatch == mon_dispatch_postauth20 ? "postauth" : "preauth");

	sshbuf_free(logmsg);
	মুক্ত(বার্তা);

	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
monitor_read(কাঠামো ssh *ssh, কাঠামো monitor *pmonitor, কাঠামো mon_table *ent,
    কাঠামো mon_table **pent)
{
	কাঠামো sshbuf *m;
	পূর্ণসংখ্যা r, ret;
	u_char type;
	কাঠামো pollfd pfd[2];

	জন্য (;;) {
		memset(&pfd, 0, আকার(pfd));
		pfd[0].fd = pmonitor->m_sendfd;
		pfd[0].events = POLLIN;
		pfd[1].fd = pmonitor->m_log_recvfd;
		pfd[1].events = pfd[1].fd == -1 ? 0 : POLLIN;
		যদি (poll(pfd, pfd[1].fd == -1 ? 1 : 2, -1) == -1) {
			যদি (errno == EINTR || errno == EAGAIN)
				চালু;
			fatal_f("poll: %s", strerror(errno));
		}
		যদি (pfd[1].revents) {
			/*
			 * Drain all log messages before processing next
			 * monitor request.
			 */
			monitor_read_log(pmonitor);
			চালু;
		}
		যদি (pfd[0].revents)
			বিরতি;  /* Continues below */
	}

	যদি ((m = sshbuf_new()) == ফাঁকা)
		fatal_f("sshbuf_new");

	mm_request_receive(pmonitor->m_sendfd, m);
	যদি ((r = sshbuf_get_u8(m, &type)) != 0)
		fatal_fr(r, "parse type");

	debug3_f("checking request %d", type);

	যখন (ent->f != ফাঁকা) {
		যদি (ent->type == type)
			বিরতি;
		ent++;
	}

	যদি (ent->f != ফাঁকা) {
		যদি (!(ent->flags & MON_PERMIT))
			fatal_f("unpermitted request %d", type);
		ret = (*ent->f)(ssh, pmonitor->m_sendfd, m);
		sshbuf_free(m);

		/* The child may use this request only once, disable it */
		যদি (ent->flags & MON_ONCE) {
			debug2_f("%d used once, disabling now", type);
			ent->flags &= ~MON_PERMIT;
		}

		যদি (pent != ফাঁকা)
			*pent = ent;

		ফেরত ret;
	}

	fatal_f("unsupported request: %d", type);

	/* NOTREACHED */
	ফেরত (-1);
}

/* allowed key state */
স্থির পূর্ণসংখ্যা
monitor_allowed_চাবি(ধ্রুবক u_char *blob, u_int bloblen)
{
	/* make sure key is allowed */
	যদি (চাবি_blob == ফাঁকা || চাবি_bloblen != bloblen ||
	    timingsafe_bcmp(চাবি_blob, blob, চাবি_bloblen))
		ফেরত (0);
	ফেরত (1);
}

স্থির শূন্য
monitor_reset_চাবি_state(শূন্য)
{
	/* reset state */
	মুক্ত(চাবি_blob);
	মুক্ত(hostbased_cuser);
	মুক্ত(hostbased_chost);
	sshauthopt_free(চাবি_opts);
	চাবি_blob = ফাঁকা;
	চাবি_bloblen = 0;
	চাবি_blobtype = MM_NOKEY;
	চাবি_opts = ফাঁকা;
	hostbased_cuser = ফাঁকা;
	hostbased_chost = ফাঁকা;
}

পূর্ণসংখ্যা
mm_answer_state(কাঠামো ssh *ssh, পূর্ণসংখ্যা sock, কাঠামো sshbuf *unused)
{
	কাঠামো sshbuf *m = ফাঁকা, *config = ফাঁকা, *hostkeys = ফাঁকা;
	কাঠামো sshbuf *opts = ফাঁকা, *confdata = ফাঁকা;
	পূর্ণসংখ্যা postauth;
	পূর্ণসংখ্যা r;

	debug_f("config len %zu", sshbuf_len(cfg));

	যদি ((m = sshbuf_new()) == ফাঁকা ||
	    (config = sshbuf_new()) == ফাঁকা ||
	    (opts = sshbuf_new()) == ফাঁকা ||
	    (confdata = sshbuf_new()) == ফাঁকা)
		fatal_f("sshbuf_new failed");

	hostkeys = pack_hostkeys();
	যদি ((r = serialise_server_options(&options, &config)) != 0)
		fatal_fr(r, "serialise_server_options");

	/*
	 * Protocol from monitor to unpriv privsep process:
	 *	string	configuration_blob
	 *	uint64	timing_secret	XXX move delays to monitor and remove
	 *	string	host_keys[] {
	 *		string public_key
	 *		string certificate
	 *	}
	 *	string  server_banner
	 *	string  client_banner
	 *	string	configuration_data (postauth)
	 *	string  keystate (postauth)
	 *	string  authenticated_user (postauth)
	 *	string  session_info (postauth)
	 *	string  authopts (postauth)
	 */
	যদি ((r = sshbuf_put_stringb(m, config)) != 0 ||
	    (r = sshbuf_put_u64(m, options.timing_secret)) != 0 ||
	    (r = sshbuf_put_stringb(m, hostkeys)) != 0 ||
	    (r = sshbuf_put_stringb(m, ssh->kex->server_version)) != 0 ||
	    (r = sshbuf_put_stringb(m, ssh->kex->client_version)) != 0)
		fatal_fr(r, "compose config");

	postauth = (authctxt && authctxt->pw && authctxt->authenticated);
	যদি (postauth) {
		/* XXX shouldn't be reachable */
		fatal_f("internal error: called in postauth");
	}

	sshbuf_free(config);
	sshbuf_free(opts);
	sshbuf_free(confdata);
	sshbuf_free(hostkeys);

	mm_request_send(sock, MONITOR_ANS_STATE, m);
	sshbuf_free(m);
	debug3_f("done");

	ফেরত (0);
}

#ifdef WITH_OPENSSL
পূর্ণসংখ্যা
mm_answer_moduli(কাঠামো ssh *ssh, পূর্ণসংখ্যা sock, কাঠামো sshbuf *m)
{
	DH *dh;
	ধ্রুবক BIGNUM *dh_p, *dh_g;
	পূর্ণসংখ্যা r;
	u_int min, want, max;

	যদি ((r = sshbuf_get_u32(m, &min)) != 0 ||
	    (r = sshbuf_get_u32(m, &want)) != 0 ||
	    (r = sshbuf_get_u32(m, &max)) != 0)
		fatal_fr(r, "parse");

	debug3_f("got parameters: %d %d %d", min, want, max);
	/* We need to check here, too, in case the child got corrupted */
	যদি (max < min || want < min || max < want)
		fatal_f("bad parameters: %d %d %d", min, want, max);

	sshbuf_reset(m);

	dh = choose_dh(min, want, max);
	যদি (dh == ফাঁকা) {
		যদি ((r = sshbuf_put_u8(m, 0)) != 0)
			fatal_fr(r, "assemble empty");
	} অন্যথা {
		/* Send first bignum */
		DH_get0_pqg(dh, &dh_p, ফাঁকা, &dh_g);
		যদি ((r = sshbuf_put_u8(m, 1)) != 0 ||
		    (r = sshbuf_put_bignum2(m, dh_p)) != 0 ||
		    (r = sshbuf_put_bignum2(m, dh_g)) != 0)
			fatal_fr(r, "assemble");

		DH_free(dh);
	}
	mm_request_send(sock, MONITOR_ANS_MODULI, m);
	ফেরত (0);
}
#endif

পূর্ণসংখ্যা
mm_answer_setcompat(কাঠামো ssh *ssh, পূর্ণসংখ্যা sock, কাঠামো sshbuf *m)
{
	পূর্ণসংখ্যা r;

	debug3_f("entering");

	যদি ((r = sshbuf_get_u32(m, &ssh->compat)) != 0)
		fatal_fr(r, "parse");
	compat_set = 1;

	ফেরত (0);
}

পূর্ণসংখ্যা
mm_answer_sign(কাঠামো ssh *ssh, পূর্ণসংখ্যা sock, কাঠামো sshbuf *m)
{
	বাহ্যিক পূর্ণসংখ্যা auth_sock;			/* XXX move to state struct? */
	কাঠামো sshkey *pubkey, *চাবি;
	কাঠামো sshbuf *sigbuf = ফাঁকা;
	u_char *p = ফাঁকা, *signature = ফাঁকা;
	অক্ষর *alg = ফাঁকা;
	আকার_t datlen, siglen;
	পূর্ণসংখ্যা r, is_proof = 0, keyid;
	u_int compat;
	ধ্রুবক অক্ষর proof_req[] = "hostkeys-prove-00@openssh.com";
	স্থির পূর্ণসংখ্যা nhostkey_proofs_done, *hostkey_proofs_done;

	debug3_f("entering");

	/* Make sure the unpriv process sent the compat bits already */
	যদি (!compat_set)
		fatal_f("state error: setcompat never called");

	যদি ((r = sshkey_froms(m, &pubkey)) != 0 ||
	    (r = sshbuf_get_string(m, &p, &datlen)) != 0 ||
	    (r = sshbuf_get_cstring(m, &alg, ফাঁকা)) != 0 ||
	    (r = sshbuf_get_u32(m, &compat)) != 0)
		fatal_fr(r, "parse");

	যদি ((keyid = get_hostkey_সূচক(pubkey, 1, ssh)) == -1)
		fatal_f("unknown hostkey");
	debug_f("hostkey %s index %d", sshkey_ssh_name(pubkey), keyid);
	sshkey_free(pubkey);

	/*
	 * Supported KEX types use SHA1 (20 bytes), SHA256 (32 bytes),
	 * SHA384 (48 bytes) and SHA512 (64 bytes).
	 *
	 * Otherwise, verify the signature request is for a hostkey
	 * proof.
	 *
	 * XXX perform similar check for KEX signature requests too?
	 * it's not trivial, since what is signed is the hash, rather
	 * than the full kex structure...
	 */
	যদি (datlen != 20 && datlen != 32 && datlen != 48 && datlen != 64) {
		/*
		 * Construct expected hostkey proof and compare it to what
		 * the client sent us.
		 */
		যদি (session_id2_len == 0) /* hostkeys is never first */
			fatal_f("bad data length: %zu", datlen);
		যদি ((চাবি = get_hostkey_public_by_সূচক(keyid, ssh)) == ফাঁকা)
			fatal_f("no hostkey for index %d", keyid);
		যদি (keyid >= nhostkey_proofs_done) {
			hostkey_proofs_done = xrecallocarray(
			    hostkey_proofs_done, nhostkey_proofs_done,
			    keyid + 1, আকার(*hostkey_proofs_done));
			nhostkey_proofs_done = keyid + 1;
		}
		যদি (hostkey_proofs_done[keyid]) {
			fatal_f("hostkeys proof requested for %s key %d "
			    "multiple times", sshkey_type(চাবি), keyid);
		}
		hostkey_proofs_done[keyid] = 1;
		যদি ((sigbuf = sshbuf_new()) == ফাঁকা)
			fatal_f("sshbuf_new");
		যদি ((r = sshbuf_put_cstring(sigbuf, proof_req)) != 0 ||
		    (r = sshbuf_put_string(sigbuf, session_id2,
		    session_id2_len)) != 0 ||
		    (r = sshkey_puts(চাবি, sigbuf)) != 0)
			fatal_fr(r, "assemble private key proof");
		যদি (datlen != sshbuf_len(sigbuf) ||
		    memcmp(p, sshbuf_ptr(sigbuf), sshbuf_len(sigbuf)) != 0)
			fatal_f("bad data length: %zu, hostkey proof len %zu",
			    datlen, sshbuf_len(sigbuf));
		sshbuf_free(sigbuf);
		is_proof = 1;
	}

	/* save session id, it will be passed on the first call */
	যদি (session_id2_len == 0) {
		session_id2_len = datlen;
		session_id2 = xmalloc(session_id2_len);
		memcpy(session_id2, p, session_id2_len);
	}

	যদি ((চাবি = get_hostkey_by_সূচক(keyid)) != ফাঁকা) {
		যদি ((r = sshkey_sign(চাবি, &signature, &siglen, p, datlen, alg,
		    options.sk_provider, ফাঁকা, compat)) != 0)
			fatal_fr(r, "sign");
	} অন্যথা যদি ((চাবি = get_hostkey_public_by_সূচক(keyid, ssh)) != ফাঁকা &&
	    auth_sock > 0) {
		যদি ((r = ssh_agent_sign(auth_sock, চাবি, &signature, &siglen,
		    p, datlen, alg, compat)) != 0)
			fatal_fr(r, "agent sign");
	} অন্যথা
		fatal_f("no hostkey from index %d", keyid);

	debug3_f("%s %s signature len=%zu", alg,
	    is_proof ? "hostkey proof" : "KEX", siglen);

	sshbuf_reset(m);
	যদি ((r = sshbuf_put_string(m, signature, siglen)) != 0)
		fatal_fr(r, "assemble");

	মুক্ত(alg);
	মুক্ত(p);
	মুক্ত(signature);

	mm_request_send(sock, MONITOR_ANS_SIGN, m);

	/* Turn on permissions for getpwnam */
	monitor_permit(mon_dispatch, MONITOR_REQ_PWNAM, 1);

	ফেরত (0);
}

#define PUTPW(b, id) \
	করো { \
		যদি ((r = sshbuf_put_string(b, \
		    &pwent->id, আকার(pwent->id))) != 0) \
			fatal_fr(r, "assemble %s", #id); \
	} যখন (0)

শূন্য
mm_encode_server_options(কাঠামো sshbuf *m)
{
	পূর্ণসংখ্যা r;
	কাঠামো sshbuf *config;

	যদি ((config = sshbuf_new()) == ফাঁকা)
		fatal_f("sshbuf_new failed");
	যদি ((r = serialise_server_options(&options, &config)) != 0)
		fatal_fr(r, "serialise_server_options");
	যদি ((r = sshbuf_put_stringb(m, config)) != 0)
		fatal_fr(r, "assemble options");
	sshbuf_free(config);
}

/* Retrieves the password entry and also checks if the user is permitted */
পূর্ণসংখ্যা
mm_answer_pwnamallow(কাঠামো ssh *ssh, পূর্ণসংখ্যা sock, কাঠামো sshbuf *m)
{
	কাঠামো passwd *pwent;
	পূর্ণসংখ্যা r, allowed = 0;

	debug3_f("entering");

	/* Make sure the unpriv process sent the compat bits already */
	যদি (!compat_set)
		fatal_f("state error: setcompat never called");

	যদি (authctxt->attempt++ != 0)
		fatal_f("multiple attempts for getpwnam");

	যদি ((r = sshbuf_get_cstring(m, &authctxt->user, ফাঁকা)) != 0)
		fatal_fr(r, "parse");

	pwent = getpwnamallow(ssh, authctxt->user);

	setproctitle("%s [priv]", pwent ? authctxt->user : "unknown");

	sshbuf_reset(m);

	যদি (pwent == ফাঁকা) {
		invalid_user = 1;
		যদি ((r = sshbuf_put_u8(m, 0)) != 0)
			fatal_fr(r, "assemble fakepw");
		authctxt->pw = fakepw();
		যাও out;
	}

	allowed = 1;
	authctxt->pw = pwent;
	authctxt->valid = 1;

	/* XXX send fake class/dir/shell, etc. */
	যদি ((r = sshbuf_put_u8(m, 1)) != 0)
		fatal_fr(r, "assemble ok");
	PUTPW(m, pw_uid);
	PUTPW(m, pw_gid);
#ifdef HAVE_STRUCT_PASSWD_PW_CHANGE
	PUTPW(m, pw_change);
#endif
#ifdef HAVE_STRUCT_PASSWD_PW_EXPIRE
	PUTPW(m, pw_expire);
#endif
	যদি ((r = sshbuf_put_cstring(m, pwent->pw_name)) != 0 ||
	    (r = sshbuf_put_cstring(m, "*")) != 0 ||
#ifdef HAVE_STRUCT_PASSWD_PW_GECOS
	    (r = sshbuf_put_cstring(m, pwent->pw_gecos)) != 0 ||
#endif
#ifdef HAVE_STRUCT_PASSWD_PW_CLASS
	    (r = sshbuf_put_cstring(m, pwent->pw_class)) != 0 ||
#endif
	    (r = sshbuf_put_cstring(m, pwent->pw_dir)) != 0 ||
	    (r = sshbuf_put_cstring(m, pwent->pw_shell)) != 0)
		fatal_fr(r, "assemble pw");

 out:
	ssh_packet_set_log_preamble(ssh, "%suser %s",
	    authctxt->valid ? "authenticating" : "invalid ", authctxt->user);

	যদি (options.refuse_connection) {
		logit("administratively prohibited connection for "
		    "%s%s from %.128s port %d",
		    authctxt->valid ? "" : "invalid user ",
		    authctxt->user, ssh_remote_ipaddr(ssh),
		    ssh_remote_port(ssh));
		cleanup_exit(EXIT_CONFIG_REFUSED);
	}

	/* Send active options to unpriv */
	mm_encode_server_options(m);

	/* Create valid auth method lists */
	যদি (auth2_setup_methods_lists(authctxt) != 0) {
		/*
		 * The monitor will continue long enough to let the child
		 * run to its packet_disconnect(), but it must not allow any
		 * authentication to succeed.
		 */
		debug_f("no valid authentication method lists");
	}

	debug3_f("sending MONITOR_ANS_PWNAM: %d", allowed);
	mm_request_send(sock, MONITOR_ANS_PWNAM, m);

	/* Allow service/style information on the auth context */
	monitor_permit(mon_dispatch, MONITOR_REQ_AUTHSERV, 1);
	monitor_permit(mon_dispatch, MONITOR_REQ_AUTH2_READ_BANNER, 1);

#ifdef USE_PAM
	যদি (options.use_pam)
		monitor_permit(mon_dispatch, MONITOR_REQ_PAM_START, 1);
#endif

	ফেরত (0);
}

পূর্ণসংখ্যা mm_answer_auth2_read_banner(কাঠামো ssh *ssh, পূর্ণসংখ্যা sock, কাঠামো sshbuf *m)
{
	অক্ষর *banner;
	পূর্ণসংখ্যা r;

	sshbuf_reset(m);
	banner = auth2_read_banner();
	যদি ((r = sshbuf_put_cstring(m, banner != ফাঁকা ? banner : "")) != 0)
		fatal_fr(r, "assemble");
	mm_request_send(sock, MONITOR_ANS_AUTH2_READ_BANNER, m);
	মুক্ত(banner);

	ফেরত (0);
}

পূর্ণসংখ্যা
mm_answer_authserv(কাঠামো ssh *ssh, পূর্ণসংখ্যা sock, কাঠামো sshbuf *m)
{
	পূর্ণসংখ্যা r;

	monitor_permit_authentications(1);

	যদি ((r = sshbuf_get_cstring(m, &authctxt->service, ফাঁকা)) != 0 ||
	    (r = sshbuf_get_cstring(m, &authctxt->style, ফাঁকা)) != 0)
		fatal_fr(r, "parse");
	debug3_f("service=%s, style=%s", authctxt->service, authctxt->style);

	যদি (strlen(authctxt->style) == 0) {
		মুক্ত(authctxt->style);
		authctxt->style = ফাঁকা;
	}

	ফেরত (0);
}

/*
 * Check that the key type appears in the supplied pattern list, ignoring
 * mismatches in the signature algorithm. (Signature algorithm checks are
 * performed in the unprivileged authentication code).
 * Returns 1 on success, 0 otherwise.
 */
স্থির পূর্ণসংখ্যা
চাবি_base_type_match(ধ্রুবক অক্ষর *method, ধ্রুবক কাঠামো sshkey *চাবি,
    ধ্রুবক অক্ষর *list)
{
	অক্ষর *s, *l, *ol = xstrdup(list);
	পূর্ণসংখ্যা found = 0;

	l = ol;
	জন্য ((s = strsep(&l, ",")); s && *s != '\0'; (s = strsep(&l, ","))) {
		যদি (sshkey_type_from_name(s) == চাবি->type) {
			found = 1;
			বিরতি;
		}
	}
	যদি (!found) {
		error("%s key type %s is not in permitted list %s", method,
		    sshkey_ssh_name(চাবি), list);
	}

	মুক্ত(ol);
	ফেরত found;
}

পূর্ণসংখ্যা
mm_answer_authpassword(কাঠামো ssh *ssh, পূর্ণসংখ্যা sock, কাঠামো sshbuf *m)
{
	স্থির পূর্ণসংখ্যা call_গুনতি;
	অক্ষর *passwd;
	পূর্ণসংখ্যা r, authenticated;
	আকার_t plen;

	যদি (!options.password_authentication)
		fatal_f("password authentication not enabled");
	যদি ((r = sshbuf_get_cstring(m, &passwd, &plen)) != 0)
		fatal_fr(r, "parse");
	/* Only authenticate if the context is valid */
	authenticated = options.password_authentication &&
	    auth_password(ssh, passwd);
	freezero(passwd, plen);

	sshbuf_reset(m);
	যদি ((r = sshbuf_put_u32(m, authenticated)) != 0)
		fatal_fr(r, "assemble");
#ifdef USE_PAM
	যদি ((r = sshbuf_put_u32(m, sshpam_get_maxtries_reached())) != 0)
		fatal_fr(r, "assemble PAM");
#endif

	debug3_f("sending result %d", authenticated);
	mm_request_send(sock, MONITOR_ANS_AUTHPASSWORD, m);

	call_গুনতি++;
	যদি (plen == 0 && call_গুনতি == 1)
		auth_method = "none";
	অন্যথা
		auth_method = "password";

	/* Causes monitor loop to terminate if authenticated */
	ফেরত (authenticated);
}

#ifdef BSD_AUTH
পূর্ণসংখ্যা
mm_answer_bsdauthquery(কাঠামো ssh *ssh, পূর্ণসংখ্যা sock, কাঠামো sshbuf *m)
{
	অক্ষর *name, *infotxt;
	u_int numprompts, *echo_on, success;
	অক্ষর **prompts;
	পূর্ণসংখ্যা r;

	যদি (!options.kbd_interactive_authentication)
		fatal_f("kbd-int authentication not enabled");
	success = bsdauth_query(authctxt, &name, &infotxt, &numprompts,
	    &prompts, &echo_on) < 0 ? 0 : 1;

	sshbuf_reset(m);
	যদি ((r = sshbuf_put_u32(m, success)) != 0)
		fatal_fr(r, "assemble");
	যদি (success) {
		যদি ((r = sshbuf_put_cstring(m, prompts[0])) != 0)
			fatal_fr(r, "assemble prompt");
	}

	debug3_f("sending challenge success: %u", success);
	mm_request_send(sock, MONITOR_ANS_BSDAUTHQUERY, m);

	যদি (success) {
		মুক্ত(name);
		মুক্ত(infotxt);
		মুক্ত(prompts);
		মুক্ত(echo_on);
	}

	ফেরত (0);
}

পূর্ণসংখ্যা
mm_answer_bsdauthrespond(কাঠামো ssh *ssh, পূর্ণসংখ্যা sock, কাঠামো sshbuf *m)
{
	অক্ষর *response;
	পূর্ণসংখ্যা r, authok;

	যদি (!options.kbd_interactive_authentication)
		fatal_f("kbd-int authentication not enabled");
	যদি (authctxt->as == ফাঁকা)
		fatal_f("no bsd auth session");

	যদি ((r = sshbuf_get_cstring(m, &response, ফাঁকা)) != 0)
		fatal_fr(r, "parse");
	authok = options.kbd_interactive_authentication &&
	    auth_userresponse(authctxt->as, response, 0);
	authctxt->as = ফাঁকা;
	debug3_f("<%s> = <%d>", response, authok);
	মুক্ত(response);

	sshbuf_reset(m);
	যদি ((r = sshbuf_put_u32(m, authok)) != 0)
		fatal_fr(r, "assemble");

	debug3_f("sending authenticated: %d", authok);
	mm_request_send(sock, MONITOR_ANS_BSDAUTHRESPOND, m);

	auth_method = "keyboard-interactive";
	auth_submethod = "bsdauth";

	ফেরত (authok != 0);
}
#endif

#ifdef USE_PAM
পূর্ণসংখ্যা
mm_answer_pam_start(কাঠামো ssh *ssh, পূর্ণসংখ্যা sock, কাঠামো sshbuf *m)
{
	যদি (!options.use_pam)
		fatal_f("UsePAM not set, but ended up in %s anyway", __func__);

	start_pam(ssh);

	monitor_permit(mon_dispatch, MONITOR_REQ_PAM_ACCOUNT, 1);
	যদি (options.kbd_interactive_authentication)
		monitor_permit(mon_dispatch, MONITOR_REQ_PAM_INIT_CTX, 1);

	ফেরত (0);
}

পূর্ণসংখ্যা
mm_answer_pam_account(কাঠামো ssh *ssh, পূর্ণসংখ্যা sock, কাঠামো sshbuf *m)
{
	u_int ret;
	পূর্ণসংখ্যা r;

	যদি (!options.use_pam)
		fatal_f("PAM not enabled");

	ret = do_pam_account();

	যদি ((r = sshbuf_put_u32(m, ret)) != 0 ||
	    (r = sshbuf_put_stringb(m, loginmsg)) != 0)
		fatal_fr(r, "buffer error");
	sshbuf_reset(loginmsg);

	mm_request_send(sock, MONITOR_ANS_PAM_ACCOUNT, m);

	ফেরত (ret);
}

স্থির শূন্য *sshpam_ctxt, *sshpam_authok;
বাহ্যিক KbdintDevice sshpam_device;

পূর্ণসংখ্যা
mm_answer_pam_init_ctx(কাঠামো ssh *ssh, পূর্ণসংখ্যা sock, কাঠামো sshbuf *m)
{
	u_int ok = 0;
	পূর্ণসংখ্যা r;

	debug3_f("entering");
	যদি (!options.kbd_interactive_authentication)
		fatal_f("kbd-int authentication not enabled");
	যদি (sshpam_ctxt != ফাঁকা)
		fatal_f("already called");
	sshpam_ctxt = (sshpam_device.init_ctx)(authctxt);
	sshpam_authok = ফাঁকা;
	sshbuf_reset(m);
	যদি (sshpam_ctxt != ফাঁকা) {
		monitor_permit(mon_dispatch, MONITOR_REQ_PAM_FREE_CTX, 1);
		monitor_permit(mon_dispatch, MONITOR_REQ_PAM_QUERY, 1);
		ok = 1;
	}
	যদি ((r = sshbuf_put_u32(m, ok)) != 0)
		fatal_fr(r, "buffer error");
	mm_request_send(sock, MONITOR_ANS_PAM_INIT_CTX, m);
	ফেরত (0);
}

পূর্ণসংখ্যা
mm_answer_pam_query(কাঠামো ssh *ssh, পূর্ণসংখ্যা sock, কাঠামো sshbuf *m)
{
	অক্ষর *name = ফাঁকা, *info = ফাঁকা, **prompts = ফাঁকা;
	u_int i, অঙ্ক = 0, *echo_on = 0;
	পূর্ণসংখ্যা r, ret;

	debug3_f("entering");
	sshpam_authok = ফাঁকা;
	যদি (sshpam_ctxt == ফাঁকা)
		fatal_f("no context");
	ret = (sshpam_device.query)(sshpam_ctxt, &name, &info,
	    &অঙ্ক, &prompts, &echo_on);
	যদি (ret == 0 && অঙ্ক == 0 && sshpam_priv_kbdint_authdone(sshpam_ctxt))
		sshpam_authok = sshpam_ctxt;
	যদি (অঙ্ক > 1 || name == ফাঁকা || info == ফাঁকা)
		fatal("sshpam_device.query failed");
	monitor_permit(mon_dispatch, MONITOR_REQ_PAM_RESPOND, 1);
	sshbuf_reset(m);
	যদি ((r = sshbuf_put_u32(m, ret)) != 0 ||
	    (r = sshbuf_put_cstring(m, name)) != 0 ||
	    (r = sshbuf_put_cstring(m, info)) != 0 ||
	    (r = sshbuf_put_u32(m, sshpam_get_maxtries_reached())) != 0 ||
	    (r = sshbuf_put_u32(m, অঙ্ক)) != 0)
		fatal_fr(r, "buffer error");
	মুক্ত(name);
	মুক্ত(info);
	জন্য (i = 0; i < অঙ্ক; ++i) {
		যদি ((r = sshbuf_put_cstring(m, prompts[i])) != 0 ||
		    (r = sshbuf_put_u32(m, echo_on[i])) != 0)
			fatal_fr(r, "buffer error");
		মুক্ত(prompts[i]);
	}
	মুক্ত(prompts);
	মুক্ত(echo_on);
	auth_method = "keyboard-interactive";
	auth_submethod = "pam";
	mm_request_send(sock, MONITOR_ANS_PAM_QUERY, m);
	ফেরত (0);
}

পূর্ণসংখ্যা
mm_answer_pam_respond(কাঠামো ssh *ssh, পূর্ণসংখ্যা sock, কাঠামো sshbuf *m)
{
	অক্ষর **resp;
	u_int i, অঙ্ক;
	পূর্ণসংখ্যা r, ret;

	debug3_f("entering");
	যদি (sshpam_ctxt == ফাঁকা)
		fatal_f("no context");
	sshpam_authok = ফাঁকা;
	যদি ((r = sshbuf_get_u32(m, &অঙ্ক)) != 0)
		fatal_fr(r, "buffer error");
	যদি (অঙ্ক > PAM_MAX_অঙ্ক_বার্তা) {
		fatal_f("Too many PAM messages, got %u, expected <= %u",
		    অঙ্ক, (unsigned)PAM_MAX_অঙ্ক_বার্তা);
	}
	যদি (অঙ্ক > 0) {
		resp = xcalloc(অঙ্ক, আকার(অক্ষর *));
		জন্য (i = 0; i < অঙ্ক; ++i) {
			যদি ((r = sshbuf_get_cstring(m, &(resp[i]), ফাঁকা)) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
		}
		ret = (sshpam_device.respond)(sshpam_ctxt, অঙ্ক, resp);
		জন্য (i = 0; i < অঙ্ক; ++i)
			মুক্ত(resp[i]);
		মুক্ত(resp);
	} অন্যথা {
		ret = (sshpam_device.respond)(sshpam_ctxt, অঙ্ক, ফাঁকা);
	}
	sshbuf_reset(m);
	যদি ((r = sshbuf_put_u32(m, ret)) != 0)
		fatal_fr(r, "buffer error");
	mm_request_send(sock, MONITOR_ANS_PAM_RESPOND, m);
	auth_method = "keyboard-interactive";
	auth_submethod = "pam";
	যদি (ret == 0)
		sshpam_authok = sshpam_ctxt;
	ফেরত (0);
}

পূর্ণসংখ্যা
mm_answer_pam_free_ctx(কাঠামো ssh *ssh, পূর্ণসংখ্যা sock, কাঠামো sshbuf *m)
{
	পূর্ণসংখ্যা r = sshpam_authok != ফাঁকা && sshpam_authok == sshpam_ctxt;

	debug3_f("entering");
	যদি (sshpam_ctxt == ফাঁকা)
		fatal_f("no context");
	(sshpam_device.free_ctx)(sshpam_ctxt);
	sshpam_ctxt = sshpam_authok = ফাঁকা;
	sshbuf_reset(m);
	mm_request_send(sock, MONITOR_ANS_PAM_FREE_CTX, m);
	/* Allow another attempt */
	monitor_permit(mon_dispatch, MONITOR_REQ_PAM_INIT_CTX, 1);
	auth_method = "keyboard-interactive";
	auth_submethod = "pam";
	ফেরত r;
}
#endif

পূর্ণসংখ্যা
mm_answer_keyallowed(কাঠামো ssh *ssh, পূর্ণসংখ্যা sock, কাঠামো sshbuf *m)
{
	কাঠামো sshkey *চাবি = ফাঁকা;
	অক্ষর *cuser, *chost;
	u_int pubkey_auth_attempt;
	u_int type = 0;
	পূর্ণসংখ্যা r, allowed = 0;
	কাঠামো sshauthopt *opts = ফাঁকা;

	debug3_f("entering");
	যদি ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_cstring(m, &cuser, ফাঁকা)) != 0 ||
	    (r = sshbuf_get_cstring(m, &chost, ফাঁকা)) != 0 ||
	    (r = sshkey_froms(m, &চাবি)) != 0 ||
	    (r = sshbuf_get_u32(m, &pubkey_auth_attempt)) != 0)
		fatal_fr(r, "parse");

	যদি (চাবি != ফাঁকা && authctxt->valid) {
		নির্বাচন (type) {
		ক্ষেত্র MM_USERKEY:
			auth_method = "publickey";
			যদি (!options.pubkey_authentication)
				বিরতি;
			যদি (auth2_চাবি_already_used(authctxt, চাবি))
				বিরতি;
			যদি (!চাবি_base_type_match(auth_method, চাবি,
			    options.pubkey_accepted_algos))
				বিরতি;
			allowed = user_চাবি_allowed(ssh, authctxt->pw, চাবি,
			    pubkey_auth_attempt, &opts);
			বিরতি;
		ক্ষেত্র MM_HOSTKEY:
			auth_method = "hostbased";
			যদি (!options.hostbased_authentication)
				বিরতি;
			যদি (auth2_চাবি_already_used(authctxt, চাবি))
				বিরতি;
			যদি (!চাবি_base_type_match(auth_method, চাবি,
			    options.hostbased_accepted_algos))
				বিরতি;
			allowed = hostbased_চাবি_allowed(ssh, authctxt->pw,
			    cuser, chost, চাবি);
			auth2_record_info(authctxt,
			    "client user \"%.100s\", client host \"%.100s\"",
			    cuser, chost);
			বিরতি;
		পূর্বনির্ধারিত:
			fatal_f("unknown key type %u", type);
			বিরতি;
		}
	}

	debug3_f("%s authentication%s: %s key is %s", auth_method,
	    pubkey_auth_attempt ? "" : " test",
	    (চাবি == ফাঁকা || !authctxt->valid) ? "invalid" : sshkey_type(চাবি),
	    allowed ? "allowed" : "not allowed");

	auth2_record_চাবি(authctxt, 0, চাবি);

	/* clear temporarily storage (used by verify) */
	monitor_reset_চাবি_state();

	যদি (allowed) {
		/* Save temporarily for comparison in verify */
		যদি ((r = sshkey_to_blob(চাবি, &চাবি_blob, &চাবি_bloblen)) != 0)
			fatal_fr(r, "sshkey_to_blob");
		চাবি_blobtype = type;
		চাবি_opts = opts;
		hostbased_cuser = cuser;
		hostbased_chost = chost;
	} অন্যথা {
		/* Log failed attempt */
		auth_log(ssh, 0, 0, auth_method, ফাঁকা);
		মুক্ত(cuser);
		মুক্ত(chost);
	}
	sshkey_free(চাবি);

	sshbuf_reset(m);
	যদি ((r = sshbuf_put_u32(m, allowed)) != 0)
		fatal_fr(r, "assemble");
	যদি (opts != ফাঁকা && (r = sshauthopt_serialise(opts, m, 1)) != 0)
		fatal_fr(r, "sshauthopt_serialise");
	mm_request_send(sock, MONITOR_ANS_KEYALLOWED, m);

	যদি (!allowed)
		sshauthopt_free(opts);

	ফেরত (0);
}

স্থির পূর্ণসংখ্যা
monitor_valid_userblob(কাঠামো ssh *ssh, ধ্রুবক u_char *তথ্য, u_int datalen)
{
	কাঠামো sshbuf *b;
	কাঠামো sshkey *hostkey = ফাঁকা;
	ধ্রুবক u_char *p;
	অক্ষর *userstyle, *cp;
	আকার_t len;
	u_char type;
	পূর্ণসংখ্যা hostbound = 0, r, fail = 0;

	যদি ((b = sshbuf_from(তথ্য, datalen)) == ফাঁকা)
		fatal_f("sshbuf_from");

	যদি ((r = sshbuf_get_string_direct(b, &p, &len)) != 0)
		fatal_fr(r, "parse sessionid");
	যদি ((session_id2 == ফাঁকা) ||
	    (len != session_id2_len) ||
	    (timingsafe_bcmp(p, session_id2, session_id2_len) != 0))
		fail++;
	যদি ((r = sshbuf_get_u8(b, &type)) != 0)
		fatal_fr(r, "parse type");
	যদি (type != SSH2_বার্তা_USERAUTH_REQUEST)
		fail++;
	যদি ((r = sshbuf_get_cstring(b, &cp, ফাঁকা)) != 0)
		fatal_fr(r, "parse userstyle");
	xasprintf(&userstyle, "%s%s%s", authctxt->user,
	    authctxt->style ? ":" : "",
	    authctxt->style ? authctxt->style : "");
	যদি (strcmp(userstyle, cp) != 0) {
		logit("wrong user name passed to monitor: "
		    "expected %s != %.100s", userstyle, cp);
		fail++;
	}
	মুক্ত(userstyle);
	মুক্ত(cp);
	যদি ((r = sshbuf_skip_string(b)) != 0 ||	/* service */
	    (r = sshbuf_get_cstring(b, &cp, ফাঁকা)) != 0)
		fatal_fr(r, "parse method");
	যদি (strcmp("publickey", cp) != 0) {
		যদি (strcmp("publickey-hostbound-v00@openssh.com", cp) == 0)
			hostbound = 1;
		অন্যথা
			fail++;
	}
	মুক্ত(cp);
	যদি ((r = sshbuf_get_u8(b, &type)) != 0)
		fatal_fr(r, "parse pktype");
	যদি (type == 0)
		fail++;
	যদি ((r = sshbuf_skip_string(b)) != 0 ||	/* pkalg */
	    (r = sshbuf_skip_string(b)) != 0 ||	/* pkblob */
	    (hostbound && (r = sshkey_froms(b, &hostkey)) != 0))
		fatal_fr(r, "parse pk");
	যদি (sshbuf_len(b) != 0)
		fail++;
	sshbuf_free(b);
	যদি (hostkey != ফাঁকা) {
		/*
		 * Ensure this is actually one of our hostkeys; unfortunately
		 * can't check ssh->kex->initial_hostkey directly at this point
		 * as packet state has not yet been exported to monitor.
		 */
		যদি (get_hostkey_সূচক(hostkey, 1, ssh) == -1)
			fatal_f("hostbound hostkey does not match");
		sshkey_free(hostkey);
	}
	ফেরত (fail == 0);
}

স্থির পূর্ণসংখ্যা
monitor_valid_hostbasedblob(ধ্রুবক u_char *তথ্য, u_int datalen,
    ধ্রুবক অক্ষর *cuser, ধ্রুবক অক্ষর *chost)
{
	কাঠামো sshbuf *b;
	ধ্রুবক u_char *p;
	অক্ষর *cp, *userstyle;
	আকার_t len;
	পূর্ণসংখ্যা r, fail = 0;
	u_char type;

	যদি ((b = sshbuf_from(তথ্য, datalen)) == ফাঁকা)
		fatal_f("sshbuf_new");
	যদি ((r = sshbuf_get_string_direct(b, &p, &len)) != 0)
		fatal_fr(r, "parse sessionid");

	যদি ((session_id2 == ফাঁকা) ||
	    (len != session_id2_len) ||
	    (timingsafe_bcmp(p, session_id2, session_id2_len) != 0))
		fail++;

	যদি ((r = sshbuf_get_u8(b, &type)) != 0)
		fatal_fr(r, "parse type");
	যদি (type != SSH2_বার্তা_USERAUTH_REQUEST)
		fail++;
	যদি ((r = sshbuf_get_cstring(b, &cp, ফাঁকা)) != 0)
		fatal_fr(r, "parse userstyle");
	xasprintf(&userstyle, "%s%s%s", authctxt->user,
	    authctxt->style ? ":" : "",
	    authctxt->style ? authctxt->style : "");
	যদি (strcmp(userstyle, cp) != 0) {
		logit("wrong user name passed to monitor: "
		    "expected %s != %.100s", userstyle, cp);
		fail++;
	}
	মুক্ত(userstyle);
	মুক্ত(cp);
	যদি ((r = sshbuf_skip_string(b)) != 0 ||	/* service */
	    (r = sshbuf_get_cstring(b, &cp, ফাঁকা)) != 0)
		fatal_fr(r, "parse method");
	যদি (strcmp(cp, "hostbased") != 0)
		fail++;
	মুক্ত(cp);
	যদি ((r = sshbuf_skip_string(b)) != 0 ||	/* pkalg */
	    (r = sshbuf_skip_string(b)) != 0)	/* pkblob */
		fatal_fr(r, "parse pk");

	/* verify client host, strip trailing dot if necessary */
	যদি ((r = sshbuf_get_cstring(b, &cp, ফাঁকা)) != 0)
		fatal_fr(r, "parse host");
	যদি (((len = strlen(cp)) > 0) && cp[len - 1] == '.')
		cp[len - 1] = '\0';
	যদি (strcmp(cp, chost) != 0)
		fail++;
	মুক্ত(cp);

	/* verify client user */
	যদি ((r = sshbuf_get_cstring(b, &cp, ফাঁকা)) != 0)
		fatal_fr(r, "parse ruser");
	যদি (strcmp(cp, cuser) != 0)
		fail++;
	মুক্ত(cp);

	যদি (sshbuf_len(b) != 0)
		fail++;
	sshbuf_free(b);
	ফেরত (fail == 0);
}

পূর্ণসংখ্যা
mm_answer_keyverify(কাঠামো ssh *ssh, পূর্ণসংখ্যা sock, কাঠামো sshbuf *m)
{
	কাঠামো sshkey *চাবি;
	ধ্রুবক u_char *signature, *তথ্য, *blob;
	অক্ষর *sigalg = ফাঁকা, *fp = ফাঁকা;
	আকার_t signaturelen, datalen, bloblen;
	পূর্ণসংখ্যা r, ret, req_presence = 0, req_verify = 0, valid_তথ্য = 0;
	পূর্ণসংখ্যা encoded_ret;
	কাঠামো sshkey_sig_details *sig_details = ফাঁকা;

	যদি ((r = sshbuf_get_string_direct(m, &blob, &bloblen)) != 0 ||
	    (r = sshbuf_get_string_direct(m, &signature, &signaturelen)) != 0 ||
	    (r = sshbuf_get_string_direct(m, &তথ্য, &datalen)) != 0 ||
	    (r = sshbuf_get_cstring(m, &sigalg, ফাঁকা)) != 0)
		fatal_fr(r, "parse");

	যদি (hostbased_cuser == ফাঁকা || hostbased_chost == ফাঁকা ||
	  !monitor_allowed_চাবি(blob, bloblen))
		fatal_f("bad key, not previously allowed");

	/* Empty signature algorithm means NULL. */
	যদি (*sigalg == '\0') {
		মুক্ত(sigalg);
		sigalg = ফাঁকা;
	}

	/* XXX use sshkey_froms here; need to change key_blob, etc. */
	যদি ((r = sshkey_from_blob(blob, bloblen, &চাবি)) != 0)
		fatal_fr(r, "parse key");

	নির্বাচন (চাবি_blobtype) {
	ক্ষেত্র MM_USERKEY:
		valid_তথ্য = monitor_valid_userblob(ssh, তথ্য, datalen);
		auth_method = "publickey";
		বিরতি;
	ক্ষেত্র MM_HOSTKEY:
		valid_তথ্য = monitor_valid_hostbasedblob(তথ্য, datalen,
		    hostbased_cuser, hostbased_chost);
		auth_method = "hostbased";
		বিরতি;
	পূর্বনির্ধারিত:
		valid_তথ্য = 0;
		বিরতি;
	}
	যদি (!valid_তথ্য)
		fatal_f("bad %s signature data blob",
		    চাবি_blobtype == MM_USERKEY ? "userkey" :
		    (চাবি_blobtype == MM_HOSTKEY ? "hostkey" : "unknown"));

	যদি ((fp = sshkey_fingerprint(চাবি, options.fingerprint_hash,
	    SSH_FP_DEFAULT)) == ফাঁকা)
		fatal_f("sshkey_fingerprint failed");

	ret = sshkey_verify(চাবি, signature, signaturelen, তথ্য, datalen,
	    sigalg, ssh->compat, &sig_details);
	debug3_f("%s %s signature using %s %s%s%s", auth_method,
	    sshkey_type(চাবি), sigalg == ফাঁকা ? "default" : sigalg,
	    (ret == 0) ? "verified" : "unverified",
	    (ret != 0) ? ": " : "", (ret != 0) ? ssh_err(ret) : "");

	যদি (ret == 0 && চাবি_blobtype == MM_USERKEY && sig_details != ফাঁকা) {
		req_presence = (options.pubkey_auth_options &
		    PUBKEYAUTH_TOUCH_REQUIRED) ||
		    !চাবি_opts->no_require_user_presence;
		যদি (req_presence &&
		    (sig_details->sk_flags & SSH_SK_USER_PRESENCE_REQD) == 0) {
			error("public key %s %s signature for %s%s from %.128s "
			    "port %d rejected: user presence "
			    "(authenticator touch) requirement not met ",
			    sshkey_type(চাবি), fp,
			    authctxt->valid ? "" : "invalid user ",
			    authctxt->user, ssh_remote_ipaddr(ssh),
			    ssh_remote_port(ssh));
			ret = SSH_ERR_SIGNATURE_INVALID;
		}
		req_verify = (options.pubkey_auth_options &
		    PUBKEYAUTH_VERIFY_REQUIRED) || চাবি_opts->require_verify;
		যদি (req_verify &&
		    (sig_details->sk_flags & SSH_SK_USER_VERIFICATION_REQD) == 0) {
			error("public key %s %s signature for %s%s from %.128s "
			    "port %d rejected: user verification requirement "
			    "not met ", sshkey_type(চাবি), fp,
			    authctxt->valid ? "" : "invalid user ",
			    authctxt->user, ssh_remote_ipaddr(ssh),
			    ssh_remote_port(ssh));
			ret = SSH_ERR_SIGNATURE_INVALID;
		}
	}
	auth2_record_চাবি(authctxt, ret == 0, চাবি);

	যদি (চাবি_blobtype == MM_USERKEY && ret == 0)
		auth_activate_options(ssh, চাবি_opts);
	monitor_reset_চাবি_state();

	sshbuf_reset(m);

	/* encode ret != 0 as positive integer, since we're sending u32 */
	encoded_ret = (ret != 0);
	যদি ((r = sshbuf_put_u32(m, encoded_ret)) != 0 ||
	    (r = sshbuf_put_u8(m, sig_details != ফাঁকা)) != 0)
		fatal_fr(r, "assemble");
	যদি (sig_details != ফাঁকা) {
		যদি ((r = sshbuf_put_u32(m, sig_details->sk_গণক)) != 0 ||
		    (r = sshbuf_put_u8(m, sig_details->sk_flags)) != 0)
			fatal_fr(r, "assemble sk");
	}
	sshkey_sig_details_free(sig_details);
	mm_request_send(sock, MONITOR_ANS_KEYVERIFY, m);

	মুক্ত(sigalg);
	মুক্ত(fp);
	sshkey_free(চাবি);

	ফেরত ret == 0;
}

স্থির শূন্য
mm_record_login(কাঠামো ssh *ssh, Session *s, কাঠামো passwd *pw)
{
	socklen_t fromlen;
	কাঠামো sockaddr_storage from;

	/*
	 * Get IP address of client. If the connection is not a socket, let
	 * the address be 0.0.0.0.
	 */
	memset(&from, 0, আকার(from));
	fromlen = আকার(from);
	যদি (ssh_packet_connection_is_on_socket(ssh)) {
		যদি (getpeername(ssh_packet_get_connection_in(ssh),
		    (কাঠামো sockaddr *)&from, &fromlen) == -1) {
			debug("getpeername: %.100s", strerror(errno));
			cleanup_exit(255);
		}
	}
	/* Record that there was a login on that tty from the remote host. */
	record_login(s->pid, s->tty, pw->pw_name, pw->pw_uid,
	    session_get_remote_name_or_ip(ssh, utmp_len, options.use_dns),
	    (কাঠামো sockaddr *)&from, fromlen);
}

স্থির শূন্য
mm_session_close(Session *s)
{
	debug3_f("session %d pid %ld", s->self, (long)s->pid);
	যদি (s->ttyfd != -1) {
		debug3_f("tty %s ptyfd %d", s->tty, s->ptyfd);
		session_pty_cleanup2(s);
	}
	session_unused(s->self);
}

পূর্ণসংখ্যা
mm_answer_pty(কাঠামো ssh *ssh, পূর্ণসংখ্যা sock, কাঠামো sshbuf *m)
{
	বাহ্যিক কাঠামো monitor *pmonitor;
	Session *s;
	পূর্ণসংখ্যা r, res, fd0;

	debug3_f("entering");

	sshbuf_reset(m);
	s = session_new();
	যদি (s == ফাঁকা)
		যাও error;
	s->authctxt = authctxt;
	s->pw = authctxt->pw;
	s->pid = pmonitor->m_pid;
	res = pty_allocate(&s->ptyfd, &s->ttyfd, s->tty, আকার(s->tty));
	যদি (res == 0)
		যাও error;
	pty_setowner(authctxt->pw, s->tty);

	যদি ((r = sshbuf_put_u32(m, 1)) != 0 ||
	    (r = sshbuf_put_cstring(m, s->tty)) != 0)
		fatal_fr(r, "assemble");

	/* We need to trick ttyslot */
	যদি (dup2(s->ttyfd, 0) == -1)
		fatal_f("dup2");

	mm_record_login(ssh, s, authctxt->pw);

	/* Now we can close the file descriptor again */
	close(0);

	/* send messages generated by record_login */
	যদি ((r = sshbuf_put_stringb(m, loginmsg)) != 0)
		fatal_fr(r, "assemble loginmsg");
	sshbuf_reset(loginmsg);

	mm_request_send(sock, MONITOR_ANS_PTY, m);

	যদি (mm_send_fd(sock, s->ptyfd) == -1 ||
	    mm_send_fd(sock, s->ttyfd) == -1)
		fatal_f("send fds failed");

	/* make sure nothing uses fd 0 */
	যদি ((fd0 = open(_PATH_DEVNULL, O_RDONLY)) == -1)
		fatal_f("open(/dev/null): %s", strerror(errno));
	যদি (fd0 != 0)
		error_f("fd0 %d != 0", fd0);

	/* slave side of pty is not needed */
	close(s->ttyfd);
	s->ttyfd = s->ptyfd;
	/* no need to dup() because nobody closes ptyfd */
	s->ptymaster = s->ptyfd;

	debug3_f("tty %s ptyfd %d", s->tty, s->ttyfd);

	ফেরত (0);

 error:
	যদি (s != ফাঁকা)
		mm_session_close(s);
	যদি ((r = sshbuf_put_u32(m, 0)) != 0)
		fatal_fr(r, "assemble 0");
	mm_request_send(sock, MONITOR_ANS_PTY, m);
	ফেরত (0);
}

পূর্ণসংখ্যা
mm_answer_pty_cleanup(কাঠামো ssh *ssh, পূর্ণসংখ্যা sock, কাঠামো sshbuf *m)
{
	Session *s;
	অক্ষর *tty;
	পূর্ণসংখ্যা r;

	debug3_f("entering");

	যদি ((r = sshbuf_get_cstring(m, &tty, ফাঁকা)) != 0)
		fatal_fr(r, "parse tty");
	যদি ((s = session_by_tty(tty)) != ফাঁকা)
		mm_session_close(s);
	sshbuf_reset(m);
	মুক্ত(tty);
	ফেরত (0);
}

পূর্ণসংখ্যা
mm_answer_term(কাঠামো ssh *ssh, পূর্ণসংখ্যা sock, কাঠামো sshbuf *req)
{
	বাহ্যিক কাঠামো monitor *pmonitor;
	পূর্ণসংখ্যা res, status;

	debug3_f("tearing down sessions");

	/* The child is terminating */
	session_destroy_all(ssh, &mm_session_close);

#ifdef USE_PAM
	যদি (options.use_pam)
		sshpam_cleanup();
#endif

	যখন (waitpid(pmonitor->m_pid, &status, 0) == -1)
		যদি (errno != EINTR)
			exit(1);

	res = WIFEXITED(status) ? WEXITSTATUS(status) : 1;

	/* Terminate process */
	exit(res);
}

#ifdef SSH_AUDIT_EVENTS
/* Report that an audit event occurred */
পূর্ণসংখ্যা
mm_answer_audit_event(কাঠামো ssh *ssh, পূর্ণসংখ্যা socket, কাঠামো sshbuf *m)
{
	u_int n;
	ssh_audit_event_t event;
	পূর্ণসংখ্যা r;

	debug3_f("entering");

	যদি ((r = sshbuf_get_u32(m, &n)) != 0)
		fatal_fr(r, "buffer error");
	event = (ssh_audit_event_t)n;
	নির্বাচন (event) {
	ক্ষেত্র SSH_AUTH_FAIL_PUBKEY:
	ক্ষেত্র SSH_AUTH_FAIL_HOSTBASED:
	ক্ষেত্র SSH_AUTH_FAIL_GSSAPI:
	ক্ষেত্র SSH_LOGIN_EXCEED_MAXTRIES:
	ক্ষেত্র SSH_LOGIN_মূল_DENIED:
	ক্ষেত্র SSH_CONNECTION_CLOSE:
	ক্ষেত্র SSH_INVALID_USER:
		audit_event(ssh, event);
		বিরতি;
	পূর্বনির্ধারিত:
		fatal("Audit event type %d not permitted", event);
	}

	ফেরত (0);
}

পূর্ণসংখ্যা
mm_answer_audit_command(কাঠামো ssh *ssh, পূর্ণসংখ্যা socket, কাঠামো sshbuf *m)
{
	অক্ষর *cmd;
	পূর্ণসংখ্যা r;

	debug3_f("entering");
	যদি ((r = sshbuf_get_cstring(m, &cmd, ফাঁকা)) != 0)
		fatal_fr(r, "buffer error");
	/* sanity check command, if so how? */
	audit_run_command(cmd);
	মুক্ত(cmd);
	ফেরত (0);
}
#endif /* SSH_AUDIT_EVENTS */

শূন্য
monitor_clear_keystate(কাঠামো ssh *ssh, কাঠামো monitor *pmonitor)
{
	ssh_clear_newkeys(ssh, MODE_IN);
	ssh_clear_newkeys(ssh, MODE_OUT);
	sshbuf_free(child_state);
	child_state = ফাঁকা;
}

শূন্য
monitor_apply_keystate(কাঠামো ssh *ssh, কাঠামো monitor *pmonitor)
{
	কাঠামো kex *kex;
	পূর্ণসংখ্যা r;

	debug3_f("packet_set_state");
	যদি ((r = ssh_packet_set_state(ssh, child_state)) != 0)
		fatal_fr(r, "packet_set_state");
	sshbuf_free(child_state);
	child_state = ফাঁকা;
	যদি ((kex = ssh->kex) == ফাঁকা)
		fatal_f("internal error: ssh->kex == NULL");
	যদি (session_id2_len != sshbuf_len(ssh->kex->session_id)) {
		fatal_f("incorrect session id length %zu (expected %u)",
		    sshbuf_len(ssh->kex->session_id), session_id2_len);
	}
	যদি (memcmp(sshbuf_ptr(ssh->kex->session_id), session_id2,
	    session_id2_len) != 0)
		fatal_f("session ID mismatch");
	/* XXX set callbacks */
#ifdef WITH_OPENSSL
	kex->kex[KEX_DH_GRP1_SHA1] = kex_gen_server;
	kex->kex[KEX_DH_GRP14_SHA1] = kex_gen_server;
	kex->kex[KEX_DH_GRP14_SHA256] = kex_gen_server;
	kex->kex[KEX_DH_GRP16_SHA512] = kex_gen_server;
	kex->kex[KEX_DH_GRP18_SHA512] = kex_gen_server;
	kex->kex[KEX_DH_GEX_SHA1] = kexgex_server;
	kex->kex[KEX_DH_GEX_SHA256] = kexgex_server;
	kex->kex[KEX_ECDH_SHA2] = kex_gen_server;
	kex->kex[KEX_KEM_MLKEM768ECDH_SHA256] = kex_gen_server;
#endif
	kex->kex[KEX_C25519_SHA256] = kex_gen_server;
	kex->kex[KEX_KEM_SNTRUP761X25519_SHA512] = kex_gen_server;
	kex->kex[KEX_KEM_MLKEM768X25519_SHA256] = kex_gen_server;
	kex->load_host_public_চাবি=&get_hostkey_public_by_type;
	kex->load_host_private_চাবি=&get_hostkey_private_by_type;
	kex->host_চাবি_সূচক=&get_hostkey_সূচক;
	kex->sign = sshd_hostkey_sign;
}

/* This function requires careful sanity checking */

শূন্য
mm_get_keystate(কাঠামো ssh *ssh, কাঠামো monitor *pmonitor)
{
	debug3_f("Waiting for new keys");

	যদি ((child_state = sshbuf_new()) == ফাঁকা)
		fatal_f("sshbuf_new failed");
	mm_request_receive_expect(pmonitor->m_sendfd, MONITOR_REQ_KEYEXPORT,
	    child_state);
	debug3_f("GOT new keys");
}


/* XXX */

স্থির শূন্য
monitor_openfds(কাঠামো monitor *mon, পূর্ণসংখ্যা do_logfds)
{
	পূর্ণসংখ্যা pair[2];
#ifdef SO_ZEROIZE
	পূর্ণসংখ্যা on = 1;
#endif

	যদি (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == -1)
		fatal_f("socketpair: %s", strerror(errno));
#ifdef SO_ZEROIZE
	যদি (setsockopt(pair[0], SOL_SOCKET, SO_ZEROIZE, &on, আকার(on)) == -1)
		error("setsockopt SO_ZEROIZE(0): %.100s", strerror(errno));
	যদি (setsockopt(pair[1], SOL_SOCKET, SO_ZEROIZE, &on, আকার(on)) == -1)
		error("setsockopt SO_ZEROIZE(1): %.100s", strerror(errno));
#endif
	FD_CLOSEONEXEC(pair[0]);
	FD_CLOSEONEXEC(pair[1]);
	mon->m_recvfd = pair[0];
	mon->m_sendfd = pair[1];

	যদি (do_logfds) {
		যদি (pipe(pair) == -1)
			fatal_f("pipe: %s", strerror(errno));
		FD_CLOSEONEXEC(pair[0]);
		FD_CLOSEONEXEC(pair[1]);
		mon->m_log_recvfd = pair[0];
		mon->m_log_sendfd = pair[1];
	} অন্যথা
		mon->m_log_recvfd = mon->m_log_sendfd = -1;
}

কাঠামো monitor *
monitor_init(শূন্য)
{
	কাঠামো monitor *mon;

	mon = xcalloc(1, আকার(*mon));
	monitor_openfds(mon, 1);

	ফেরত mon;
}

শূন্য
monitor_reinit(কাঠামো monitor *mon)
{
	monitor_openfds(mon, 0);
}

পূর্ণসংখ্যা
monitor_auth_attempted(শূন্য)
{
	ফেরত auth_attempted;
}

পূর্ণসংখ্যা
monitor_invalid_user(শূন্য)
{
	ফেরত invalid_user;
}

#ifdef GSSAPI
পূর্ণসংখ্যা
mm_answer_gss_setup_ctx(কাঠামো ssh *ssh, পূর্ণসংখ্যা sock, কাঠামো sshbuf *m)
{
	gss_OID_desc goid;
	OM_uint32 major;
	আকার_t len;
	u_char *p;
	পূর্ণসংখ্যা r;

	যদি (!options.gss_authentication)
		fatal_f("GSSAPI authentication not enabled");

	ssh_gssapi_cleanup_global_client();

	যদি ((r = sshbuf_get_string(m, &p, &len)) != 0)
		fatal_fr(r, "parse");
	goid.elements = p;
	goid.দৈর্ঘ্য = len;

	major = ssh_gssapi_server_ctx(&gsscontext, &goid);

	মুক্ত(goid.elements);

	sshbuf_reset(m);
	যদি ((r = sshbuf_put_u32(m, major)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(sock, MONITOR_ANS_GSSSETUP, m);

	/* Now we have a context, enable the step */
	monitor_permit(mon_dispatch, MONITOR_REQ_GSSSTEP, 1);

	ফেরত (0);
}

পূর্ণসংখ্যা
mm_answer_gss_accept_ctx(কাঠামো ssh *ssh, পূর্ণসংখ্যা sock, কাঠামো sshbuf *m)
{
	gss_বাফার_desc in;
	gss_বাফার_desc out = GSS_C_EMPTY_বাফার;
	OM_uint32 major, minor;
	OM_uint32 flags = 0; /* GSI needs this */
	পূর্ণসংখ্যা r;

	যদি (!options.gss_authentication)
		fatal_f("GSSAPI authentication not enabled");

	যদি ((r = ssh_gssapi_get_বাফার_desc(m, &in)) != 0)
		fatal_fr(r, "ssh_gssapi_get_buffer_desc");
	major = ssh_gssapi_accept_ctx(gsscontext, &in, &out, &flags);
	মুক্ত(in.মান);

	sshbuf_reset(m);
	যদি ((r = sshbuf_put_u32(m, major)) != 0 ||
	    (r = sshbuf_put_string(m, out.মান, out.দৈর্ঘ্য)) != 0 ||
	    (r = sshbuf_put_u32(m, flags)) != 0)
		fatal_fr(r, "assemble");
	mm_request_send(sock, MONITOR_ANS_GSSSTEP, m);

	gss_release_বাফার(&minor, &out);

	যদি (major == GSS_S_COMPLETE) {
		monitor_permit(mon_dispatch, MONITOR_REQ_GSSSTEP, 0);
		monitor_permit(mon_dispatch, MONITOR_REQ_GSSUSEROK, 1);
		monitor_permit(mon_dispatch, MONITOR_REQ_GSSCHECKMIC, 1);
	}
	ফেরত (0);
}

পূর্ণসংখ্যা
mm_answer_gss_checkmic(কাঠামো ssh *ssh, পূর্ণসংখ্যা sock, কাঠামো sshbuf *m)
{
	gss_বাফার_desc gssbuf, mic;
	OM_uint32 ret;
	পূর্ণসংখ্যা r;

	যদি (!options.gss_authentication)
		fatal_f("GSSAPI authentication not enabled");

	যদি ((r = ssh_gssapi_get_বাফার_desc(m, &gssbuf)) != 0 ||
	    (r = ssh_gssapi_get_বাফার_desc(m, &mic)) != 0)
		fatal_fr(r, "ssh_gssapi_get_buffer_desc");

	ret = ssh_gssapi_checkmic(gsscontext, &gssbuf, &mic);

	মুক্ত(gssbuf.মান);
	মুক্ত(mic.মান);

	sshbuf_reset(m);
	যদি ((r = sshbuf_put_u32(m, ret)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(sock, MONITOR_ANS_GSSCHECKMIC, m);

	যদি (!GSS_ERROR(ret))
		monitor_permit(mon_dispatch, MONITOR_REQ_GSSUSEROK, 1);

	ফেরত (0);
}

পূর্ণসংখ্যা
mm_answer_gss_userok(কাঠামো ssh *ssh, পূর্ণসংখ্যা sock, কাঠামো sshbuf *m)
{
	পূর্ণসংখ্যা r, authenticated;
	ধ্রুবক অক্ষর *displayname;

	যদি (!options.gss_authentication)
		fatal_f("GSSAPI authentication not enabled");

	authenticated = authctxt->valid && ssh_gssapi_userok(authctxt->user);

	sshbuf_reset(m);
	যদি ((r = sshbuf_put_u32(m, authenticated)) != 0)
		fatal_fr(r, "assemble");

	debug3_f("sending result %d", authenticated);
	mm_request_send(sock, MONITOR_ANS_GSSUSEROK, m);

	auth_method = "gssapi-with-mic";

	যদি ((displayname = ssh_gssapi_displayname()) != ফাঁকা)
		auth2_record_info(authctxt, "%s", displayname);

	/* Monitor loop will terminate if authenticated */
	ফেরত (authenticated);
}
#endif /* GSSAPI */

