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
স্থির Gssctxt *gsscontext = রিক্ত;
#endif

/* Imports */
বাহ্য ServerOptions options;
বাহ্য u_int utmp_len;
বাহ্য সংরচনা sshbuf *cfg;
বাহ্য সংরচনা sshbuf *loginmsg;
বাহ্য সংরচনা include_list includes;
বাহ্য সংরচনা sshauthopt *auth_opts; /* XXX move to permanent ssh->authctxt? */

/* State exported from the child */
স্থির সংরচনা sshbuf *child_state;

/* Functions on the monitor that answer unprivileged requests */

পূর্ণাঙ্ক mm_answer_moduli(সংরচনা ssh *, পূর্ণাঙ্ক, সংরচনা sshbuf *);
পূর্ণাঙ্ক mm_answer_setcompat(সংরচনা ssh *, পূর্ণাঙ্ক, সংরচনা sshbuf *);
পূর্ণাঙ্ক mm_answer_sign(সংরচনা ssh *, পূর্ণাঙ্ক, সংরচনা sshbuf *);
পূর্ণাঙ্ক mm_answer_pwnamallow(সংরচনা ssh *, পূর্ণাঙ্ক, সংরচনা sshbuf *);
পূর্ণাঙ্ক mm_answer_auth2_read_banner(সংরচনা ssh *, পূর্ণাঙ্ক, সংরচনা sshbuf *);
পূর্ণাঙ্ক mm_answer_authserv(সংরচনা ssh *, পূর্ণাঙ্ক, সংরচনা sshbuf *);
পূর্ণাঙ্ক mm_answer_authpassword(সংরচনা ssh *, পূর্ণাঙ্ক, সংরচনা sshbuf *);
পূর্ণাঙ্ক mm_answer_bsdauthquery(সংরচনা ssh *, পূর্ণাঙ্ক, সংরচনা sshbuf *);
পূর্ণাঙ্ক mm_answer_bsdauthrespond(সংরচনা ssh *, পূর্ণাঙ্ক, সংরচনা sshbuf *);
পূর্ণাঙ্ক mm_answer_keyallowed(সংরচনা ssh *, পূর্ণাঙ্ক, সংরচনা sshbuf *);
পূর্ণাঙ্ক mm_answer_keyverify(সংরচনা ssh *, পূর্ণাঙ্ক, সংরচনা sshbuf *);
পূর্ণাঙ্ক mm_answer_pty(সংরচনা ssh *, পূর্ণাঙ্ক, সংরচনা sshbuf *);
পূর্ণাঙ্ক mm_answer_pty_cleanup(সংরচনা ssh *, পূর্ণাঙ্ক, সংরচনা sshbuf *);
পূর্ণাঙ্ক mm_answer_term(সংরচনা ssh *, পূর্ণাঙ্ক, সংরচনা sshbuf *);
পূর্ণাঙ্ক mm_answer_state(সংরচনা ssh *, পূর্ণাঙ্ক, সংরচনা sshbuf *);

#ifdef USE_PAM
পূর্ণাঙ্ক mm_answer_pam_start(সংরচনা ssh *, পূর্ণাঙ্ক, সংরচনা sshbuf *);
পূর্ণাঙ্ক mm_answer_pam_account(সংরচনা ssh *, পূর্ণাঙ্ক, সংরচনা sshbuf *);
পূর্ণাঙ্ক mm_answer_pam_init_ctx(সংরচনা ssh *, পূর্ণাঙ্ক, সংরচনা sshbuf *);
পূর্ণাঙ্ক mm_answer_pam_query(সংরচনা ssh *, পূর্ণাঙ্ক, সংরচনা sshbuf *);
পূর্ণাঙ্ক mm_answer_pam_respond(সংরচনা ssh *, পূর্ণাঙ্ক, সংরচনা sshbuf *);
পূর্ণাঙ্ক mm_answer_pam_free_ctx(সংরচনা ssh *, পূর্ণাঙ্ক, সংরচনা sshbuf *);
#endif

#ifdef GSSAPI
পূর্ণাঙ্ক mm_answer_gss_setup_ctx(সংরচনা ssh *, পূর্ণাঙ্ক, সংরচনা sshbuf *);
পূর্ণাঙ্ক mm_answer_gss_accept_ctx(সংরচনা ssh *, পূর্ণাঙ্ক, সংরচনা sshbuf *);
পূর্ণাঙ্ক mm_answer_gss_userok(সংরচনা ssh *, পূর্ণাঙ্ক, সংরচনা sshbuf *);
পূর্ণাঙ্ক mm_answer_gss_checkmic(সংরচনা ssh *, পূর্ণাঙ্ক, সংরচনা sshbuf *);
#endif

#ifdef SSH_AUDIT_EVENTS
পূর্ণাঙ্ক mm_answer_audit_event(সংরচনা ssh *, পূর্ণাঙ্ক, সংরচনা sshbuf *);
পূর্ণাঙ্ক mm_answer_audit_command(সংরচনা ssh *, পূর্ণাঙ্ক, সংরচনা sshbuf *);
#endif

স্থির Authctxt *authctxt;

/* local state for key verify */
স্থির u_char *চাবি_blob = রিক্ত;
স্থির size_t চাবি_bloblen = 0;
স্থির u_int চাবি_blobtype = MM_NOKEY;
স্থির সংরচনা sshauthopt *চাবি_opts = রিক্ত;
স্থির বর্ণ *hostbased_cuser = রিক্ত;
স্থির বর্ণ *hostbased_chost = রিক্ত;
স্থির বর্ণ *auth_method = "unknown";
স্থির বর্ণ *auth_submethod = রিক্ত;
স্থির u_int session_id2_len = 0;
স্থির u_char *session_id2 = রিক্ত;
স্থির pid_t monitor_child_pid;
স্থির পূর্ণাঙ্ক auth_attempted = 0;
স্থির পূর্ণাঙ্ক invalid_user = 0;
স্থির পূর্ণাঙ্ক compat_set = 0;

সংরচনা mon_table {
	গণনা monitor_reqtype type;
	পূর্ণাঙ্ক flags;
	পূর্ণাঙ্ক (*f)(সংরচনা ssh *, পূর্ণাঙ্ক, সংরচনা sshbuf *);
};

#define MON_ISAUTH	0x0004	/* Required for Authentication */
#define MON_AUTHDECIDE	0x0008	/* Decides Authentication */
#define MON_ONCE	0x0010	/* Disable after calling */
#define MON_ALOG	0x0020	/* Log auth attempt without authenticating */

#define MON_AUTH	(MON_ISAUTH|MON_AUTHDECIDE)

#define MON_PERMIT	0x1000	/* Request is permitted */

স্থির পূর্ণাঙ্ক monitor_read(সংরচনা ssh *, সংরচনা monitor *, সংরচনা mon_table *,
    সংরচনা mon_table **);
স্থির পূর্ণাঙ্ক monitor_read_log(সংরচনা monitor *);

সংরচনা mon_table mon_dispatch_proto20[] = {
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
    {0, 0, রিক্ত}
};

সংরচনা mon_table mon_dispatch_postauth20[] = {
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
    {0, 0, রিক্ত}
};

সংরচনা mon_table *mon_dispatch;

/* Specifies if a certain message is allowed at the moment */
স্থির শূন্য
monitor_permit(সংরচনা mon_table *ent, গণনা monitor_reqtype type, পূর্ণাঙ্ক permit)
{
	যাবত্ (ent->f != রিক্ত) {
		যদি (ent->type == type) {
			ent->flags &= ~MON_PERMIT;
			ent->flags |= permit ? MON_PERMIT : 0;
			প্রত্যাগম;
		}
		ent++;
	}
}

স্থির শূন্য
monitor_permit_authentications(পূর্ণাঙ্ক permit)
{
	সংরচনা mon_table *ent = mon_dispatch;

	যাবত্ (ent->f != রিক্ত) {
		যদি (ent->flags & MON_AUTH) {
			ent->flags &= ~MON_PERMIT;
			ent->flags |= permit ? MON_PERMIT : 0;
		}
		ent++;
	}
}

শূন্য
monitor_child_preauth(সংরচনা ssh *ssh, সংরচনা monitor *pmonitor)
{
	সংরচনা mon_table *ent;
	পূর্ণাঙ্ক status, authenticated = 0, partial = 0;

	debug3("preauth child monitor started");

	যদি (pmonitor->m_recvfd >= 0)
		close(pmonitor->m_recvfd);
	যদি (pmonitor->m_log_sendfd >= 0)
		close(pmonitor->m_log_sendfd);
	pmonitor->m_log_sendfd = pmonitor->m_recvfd = -1;

	authctxt = (Authctxt *)ssh->authctxt;
	memset(authctxt, 0, পরিমাণ(*authctxt));
	ssh->authctxt = authctxt;

	authctxt->loginmsg = loginmsg;

	mon_dispatch = mon_dispatch_proto20;
	/* Permit requests for state, moduli and signatures */
	monitor_permit(mon_dispatch, MONITOR_REQ_STATE, 1);
	monitor_permit(mon_dispatch, MONITOR_REQ_MODULI, 1);
	monitor_permit(mon_dispatch, MONITOR_REQ_SETCOMPAT, 1);
	monitor_permit(mon_dispatch, MONITOR_REQ_SIGN, 1);

	/* The first few requests do not require asynchronous access */
	যাবত্ (!authenticated) {
		partial = 0;
		auth_method = "unknown";
		auth_submethod = রিক্ত;
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
				সংরচনা sshbuf *m;

				যদি ((m = sshbuf_new()) == রিক্ত)
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
	ssh->authctxt = রিক্ত;
	ssh_packet_set_log_preamble(ssh, "user %s", authctxt->user);

	mm_get_keystate(ssh, pmonitor);

	/* Drain any buffered messages from the child */
	যাবত্ (pmonitor->m_log_recvfd != -1 && monitor_read_log(pmonitor) == 0)
		;

	/* Wait for the child's exit status */
	যাবত্ (waitpid(pmonitor->m_pid, &status, 0) == -1) {
		যদি (errno == EINTR)
			অনুবর্ত;
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
monitor_child_handler(পূর্ণাঙ্ক sig)
{
	kill(monitor_child_pid, sig);
}

শূন্য
monitor_child_postauth(সংরচনা ssh *ssh, সংরচনা monitor *pmonitor)
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

	প্রতি (;;)
		monitor_read(ssh, pmonitor, mon_dispatch, রিক্ত);
}

স্থির পূর্ণাঙ্ক
monitor_read_log(সংরচনা monitor *pmonitor)
{
	সংরচনা sshbuf *logmsg;
	u_int len, level, forced;
	বর্ণ *বার্তা;
	u_char *p;
	পূর্ণাঙ্ক r;

	যদি ((logmsg = sshbuf_new()) == রিক্ত)
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
			প্রত্যাগম -1;
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
	    (r = sshbuf_get_cstring(logmsg, &বার্তা, রিক্ত)) != 0)
		fatal_fr(r, "parse");

	/* Log it */
	যদি (log_level_name(level) == রিক্ত)
		fatal_f("invalid log level %u (corrupted message?)", level);
	sshlogdirect(level, forced, "%s [%s]", বার্তা,
	    mon_dispatch == mon_dispatch_postauth20 ? "postauth" : "preauth");

	sshbuf_free(logmsg);
	মুক্ত(বার্তা);

	প্রত্যাগম 0;
}

স্থির পূর্ণাঙ্ক
monitor_read(সংরচনা ssh *ssh, সংরচনা monitor *pmonitor, সংরচনা mon_table *ent,
    সংরচনা mon_table **pent)
{
	সংরচনা sshbuf *m;
	পূর্ণাঙ্ক r, ret;
	u_char type;
	সংরচনা pollfd pfd[2];

	প্রতি (;;) {
		memset(&pfd, 0, পরিমাণ(pfd));
		pfd[0].fd = pmonitor->m_sendfd;
		pfd[0].events = POLLIN;
		pfd[1].fd = pmonitor->m_log_recvfd;
		pfd[1].events = pfd[1].fd == -1 ? 0 : POLLIN;
		যদি (poll(pfd, pfd[1].fd == -1 ? 1 : 2, -1) == -1) {
			যদি (errno == EINTR || errno == EAGAIN)
				অনুবর্ত;
			fatal_f("poll: %s", strerror(errno));
		}
		যদি (pfd[1].revents) {
			/*
			 * Drain all log messages before processing next
			 * monitor request.
			 */
			monitor_read_log(pmonitor);
			অনুবর্ত;
		}
		যদি (pfd[0].revents)
			ভঙ্গ;  /* Continues below */
	}

	যদি ((m = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new");

	mm_request_receive(pmonitor->m_sendfd, m);
	যদি ((r = sshbuf_get_u8(m, &type)) != 0)
		fatal_fr(r, "parse type");

	debug3_f("checking request %d", type);

	যাবত্ (ent->f != রিক্ত) {
		যদি (ent->type == type)
			ভঙ্গ;
		ent++;
	}

	যদি (ent->f != রিক্ত) {
		যদি (!(ent->flags & MON_PERMIT))
			fatal_f("unpermitted request %d", type);
		ret = (*ent->f)(ssh, pmonitor->m_sendfd, m);
		sshbuf_free(m);

		/* The child may use this request only once, disable it */
		যদি (ent->flags & MON_ONCE) {
			debug2_f("%d used once, disabling now", type);
			ent->flags &= ~MON_PERMIT;
		}

		যদি (pent != রিক্ত)
			*pent = ent;

		প্রত্যাগম ret;
	}

	fatal_f("unsupported request: %d", type);

	/* NOTREACHED */
	প্রত্যাগম (-1);
}

/* allowed key state */
স্থির পূর্ণাঙ্ক
monitor_allowed_চাবি(ধ্রুব u_char *blob, u_int bloblen)
{
	/* make sure key is allowed */
	যদি (চাবি_blob == রিক্ত || চাবি_bloblen != bloblen ||
	    timingsafe_bcmp(চাবি_blob, blob, চাবি_bloblen))
		প্রত্যাগম (0);
	প্রত্যাগম (1);
}

স্থির শূন্য
monitor_reset_চাবি_state(শূন্য)
{
	/* reset state */
	মুক্ত(চাবি_blob);
	মুক্ত(hostbased_cuser);
	মুক্ত(hostbased_chost);
	sshauthopt_free(চাবি_opts);
	চাবি_blob = রিক্ত;
	চাবি_bloblen = 0;
	চাবি_blobtype = MM_NOKEY;
	চাবি_opts = রিক্ত;
	hostbased_cuser = রিক্ত;
	hostbased_chost = রিক্ত;
}

পূর্ণাঙ্ক
mm_answer_state(সংরচনা ssh *ssh, পূর্ণাঙ্ক sock, সংরচনা sshbuf *unused)
{
	সংরচনা sshbuf *m = রিক্ত, *config = রিক্ত, *hostkeys = রিক্ত;
	সংরচনা sshbuf *opts = রিক্ত, *confdata = রিক্ত;
	পূর্ণাঙ্ক postauth;
	পূর্ণাঙ্ক r;

	debug_f("config len %zu", sshbuf_len(cfg));

	যদি ((m = sshbuf_new()) == রিক্ত ||
	    (config = sshbuf_new()) == রিক্ত ||
	    (opts = sshbuf_new()) == রিক্ত ||
	    (confdata = sshbuf_new()) == রিক্ত)
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

	প্রত্যাগম (0);
}

#ifdef WITH_OPENSSL
পূর্ণাঙ্ক
mm_answer_moduli(সংরচনা ssh *ssh, পূর্ণাঙ্ক sock, সংরচনা sshbuf *m)
{
	DH *dh;
	ধ্রুব BIGNUM *dh_p, *dh_g;
	পূর্ণাঙ্ক r;
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
	যদি (dh == রিক্ত) {
		যদি ((r = sshbuf_put_u8(m, 0)) != 0)
			fatal_fr(r, "assemble empty");
	} অন্যথা {
		/* Send first bignum */
		DH_get0_pqg(dh, &dh_p, রিক্ত, &dh_g);
		যদি ((r = sshbuf_put_u8(m, 1)) != 0 ||
		    (r = sshbuf_put_bignum2(m, dh_p)) != 0 ||
		    (r = sshbuf_put_bignum2(m, dh_g)) != 0)
			fatal_fr(r, "assemble");

		DH_free(dh);
	}
	mm_request_send(sock, MONITOR_ANS_MODULI, m);
	প্রত্যাগম (0);
}
#endif

পূর্ণাঙ্ক
mm_answer_setcompat(সংরচনা ssh *ssh, পূর্ণাঙ্ক sock, সংরচনা sshbuf *m)
{
	পূর্ণাঙ্ক r;

	debug3_f("entering");

	যদি ((r = sshbuf_get_u32(m, &ssh->compat)) != 0)
		fatal_fr(r, "parse");
	compat_set = 1;

	প্রত্যাগম (0);
}

পূর্ণাঙ্ক
mm_answer_sign(সংরচনা ssh *ssh, পূর্ণাঙ্ক sock, সংরচনা sshbuf *m)
{
	বাহ্য পূর্ণাঙ্ক auth_sock;			/* XXX move to state struct? */
	সংরচনা sshkey *pubkey, *চাবি;
	সংরচনা sshbuf *sigbuf = রিক্ত;
	u_char *p = রিক্ত, *signature = রিক্ত;
	বর্ণ *alg = রিক্ত;
	size_t datlen, siglen;
	পূর্ণাঙ্ক r, is_proof = 0, keyid;
	u_int compat;
	ধ্রুব বর্ণ proof_req[] = "hostkeys-prove-00@openssh.com";
	স্থির পূর্ণাঙ্ক nhostkey_proofs_done, *hostkey_proofs_done;

	debug3_f("entering");

	/* Make sure the unpriv process sent the compat bits already */
	যদি (!compat_set)
		fatal_f("state error: setcompat never called");

	যদি ((r = sshkey_froms(m, &pubkey)) != 0 ||
	    (r = sshbuf_get_string(m, &p, &datlen)) != 0 ||
	    (r = sshbuf_get_cstring(m, &alg, রিক্ত)) != 0 ||
	    (r = sshbuf_get_u32(m, &compat)) != 0)
		fatal_fr(r, "parse");

	যদি ((keyid = get_hostkey_index(pubkey, 1, ssh)) == -1)
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
		যদি ((চাবি = get_hostkey_public_by_index(keyid, ssh)) == রিক্ত)
			fatal_f("no hostkey for index %d", keyid);
		যদি (keyid >= nhostkey_proofs_done) {
			hostkey_proofs_done = xrecallocarray(
			    hostkey_proofs_done, nhostkey_proofs_done,
			    keyid + 1, পরিমাণ(*hostkey_proofs_done));
			nhostkey_proofs_done = keyid + 1;
		}
		যদি (hostkey_proofs_done[keyid]) {
			fatal_f("hostkeys proof requested for %s key %d "
			    "multiple times", sshkey_type(চাবি), keyid);
		}
		hostkey_proofs_done[keyid] = 1;
		যদি ((sigbuf = sshbuf_new()) == রিক্ত)
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

	যদি ((চাবি = get_hostkey_by_index(keyid)) != রিক্ত) {
		যদি ((r = sshkey_sign(চাবি, &signature, &siglen, p, datlen, alg,
		    options.sk_provider, রিক্ত, compat)) != 0)
			fatal_fr(r, "sign");
	} অন্যথা যদি ((চাবি = get_hostkey_public_by_index(keyid, ssh)) != রিক্ত &&
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

	প্রত্যাগম (0);
}

#define PUTPW(b, id) \
	কুরু { \
		যদি ((r = sshbuf_put_string(b, \
		    &pwent->id, পরিমাণ(pwent->id))) != 0) \
			fatal_fr(r, "assemble %s", #id); \
	} যাবত্ (0)

শূন্য
mm_encode_server_options(সংরচনা sshbuf *m)
{
	পূর্ণাঙ্ক r;
	সংরচনা sshbuf *config;

	যদি ((config = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new failed");
	যদি ((r = serialise_server_options(&options, &config)) != 0)
		fatal_fr(r, "serialise_server_options");
	যদি ((r = sshbuf_put_stringb(m, config)) != 0)
		fatal_fr(r, "assemble options");
	sshbuf_free(config);
}

/* Retrieves the password entry and also checks if the user is permitted */
পূর্ণাঙ্ক
mm_answer_pwnamallow(সংরচনা ssh *ssh, পূর্ণাঙ্ক sock, সংরচনা sshbuf *m)
{
	সংরচনা passwd *pwent;
	পূর্ণাঙ্ক r, allowed = 0;

	debug3_f("entering");

	/* Make sure the unpriv process sent the compat bits already */
	যদি (!compat_set)
		fatal_f("state error: setcompat never called");

	যদি (authctxt->attempt++ != 0)
		fatal_f("multiple attempts for getpwnam");

	যদি ((r = sshbuf_get_cstring(m, &authctxt->user, রিক্ত)) != 0)
		fatal_fr(r, "parse");

	pwent = getpwnamallow(ssh, authctxt->user);

	setproctitle("%s [priv]", pwent ? authctxt->user : "unknown");

	sshbuf_reset(m);

	যদি (pwent == রিক্ত) {
		invalid_user = 1;
		যদি ((r = sshbuf_put_u8(m, 0)) != 0)
			fatal_fr(r, "assemble fakepw");
		authctxt->pw = fakepw();
		গচ্ছ out;
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

	প্রত্যাগম (0);
}

পূর্ণাঙ্ক mm_answer_auth2_read_banner(সংরচনা ssh *ssh, পূর্ণাঙ্ক sock, সংরচনা sshbuf *m)
{
	বর্ণ *banner;
	পূর্ণাঙ্ক r;

	sshbuf_reset(m);
	banner = auth2_read_banner();
	যদি ((r = sshbuf_put_cstring(m, banner != রিক্ত ? banner : "")) != 0)
		fatal_fr(r, "assemble");
	mm_request_send(sock, MONITOR_ANS_AUTH2_READ_BANNER, m);
	মুক্ত(banner);

	প্রত্যাগম (0);
}

পূর্ণাঙ্ক
mm_answer_authserv(সংরচনা ssh *ssh, পূর্ণাঙ্ক sock, সংরচনা sshbuf *m)
{
	পূর্ণাঙ্ক r;

	monitor_permit_authentications(1);

	যদি ((r = sshbuf_get_cstring(m, &authctxt->service, রিক্ত)) != 0 ||
	    (r = sshbuf_get_cstring(m, &authctxt->style, রিক্ত)) != 0)
		fatal_fr(r, "parse");
	debug3_f("service=%s, style=%s", authctxt->service, authctxt->style);

	যদি (strlen(authctxt->style) == 0) {
		মুক্ত(authctxt->style);
		authctxt->style = রিক্ত;
	}

	প্রত্যাগম (0);
}

/*
 * Check that the key type appears in the supplied pattern list, ignoring
 * mismatches in the signature algorithm. (Signature algorithm checks are
 * performed in the unprivileged authentication code).
 * Returns 1 on success, 0 otherwise.
 */
স্থির পূর্ণাঙ্ক
চাবি_base_type_match(ধ্রুব বর্ণ *method, ধ্রুব সংরচনা sshkey *চাবি,
    ধ্রুব বর্ণ *list)
{
	বর্ণ *s, *l, *ol = xstrdup(list);
	পূর্ণাঙ্ক found = 0;

	l = ol;
	প্রতি ((s = strsep(&l, ",")); s && *s != '\0'; (s = strsep(&l, ","))) {
		যদি (sshkey_type_from_name(s) == চাবি->type) {
			found = 1;
			ভঙ্গ;
		}
	}
	যদি (!found) {
		error("%s key type %s is not in permitted list %s", method,
		    sshkey_ssh_name(চাবি), list);
	}

	মুক্ত(ol);
	প্রত্যাগম found;
}

পূর্ণাঙ্ক
mm_answer_authpassword(সংরচনা ssh *ssh, পূর্ণাঙ্ক sock, সংরচনা sshbuf *m)
{
	স্থির পূর্ণাঙ্ক call_গুনতি;
	বর্ণ *passwd;
	পূর্ণাঙ্ক r, authenticated;
	size_t plen;

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
	প্রত্যাগম (authenticated);
}

#ifdef BSD_AUTH
পূর্ণাঙ্ক
mm_answer_bsdauthquery(সংরচনা ssh *ssh, পূর্ণাঙ্ক sock, সংরচনা sshbuf *m)
{
	বর্ণ *name, *infotxt;
	u_int numprompts, *echo_on, success;
	বর্ণ **prompts;
	পূর্ণাঙ্ক r;

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

	প্রত্যাগম (0);
}

পূর্ণাঙ্ক
mm_answer_bsdauthrespond(সংরচনা ssh *ssh, পূর্ণাঙ্ক sock, সংরচনা sshbuf *m)
{
	বর্ণ *response;
	পূর্ণাঙ্ক r, authok;

	যদি (!options.kbd_interactive_authentication)
		fatal_f("kbd-int authentication not enabled");
	যদি (authctxt->as == রিক্ত)
		fatal_f("no bsd auth session");

	যদি ((r = sshbuf_get_cstring(m, &response, রিক্ত)) != 0)
		fatal_fr(r, "parse");
	authok = options.kbd_interactive_authentication &&
	    auth_userresponse(authctxt->as, response, 0);
	authctxt->as = রিক্ত;
	debug3_f("<%s> = <%d>", response, authok);
	মুক্ত(response);

	sshbuf_reset(m);
	যদি ((r = sshbuf_put_u32(m, authok)) != 0)
		fatal_fr(r, "assemble");

	debug3_f("sending authenticated: %d", authok);
	mm_request_send(sock, MONITOR_ANS_BSDAUTHRESPOND, m);

	auth_method = "keyboard-interactive";
	auth_submethod = "bsdauth";

	প্রত্যাগম (authok != 0);
}
#endif

#ifdef USE_PAM
পূর্ণাঙ্ক
mm_answer_pam_start(সংরচনা ssh *ssh, পূর্ণাঙ্ক sock, সংরচনা sshbuf *m)
{
	যদি (!options.use_pam)
		fatal_f("UsePAM not set, but ended up in %s anyway", __func__);

	start_pam(ssh);

	monitor_permit(mon_dispatch, MONITOR_REQ_PAM_ACCOUNT, 1);
	যদি (options.kbd_interactive_authentication)
		monitor_permit(mon_dispatch, MONITOR_REQ_PAM_INIT_CTX, 1);

	প্রত্যাগম (0);
}

পূর্ণাঙ্ক
mm_answer_pam_account(সংরচনা ssh *ssh, পূর্ণাঙ্ক sock, সংরচনা sshbuf *m)
{
	u_int ret;
	পূর্ণাঙ্ক r;

	যদি (!options.use_pam)
		fatal_f("PAM not enabled");

	ret = do_pam_account();

	যদি ((r = sshbuf_put_u32(m, ret)) != 0 ||
	    (r = sshbuf_put_stringb(m, loginmsg)) != 0)
		fatal_fr(r, "buffer error");
	sshbuf_reset(loginmsg);

	mm_request_send(sock, MONITOR_ANS_PAM_ACCOUNT, m);

	প্রত্যাগম (ret);
}

স্থির শূন্য *sshpam_ctxt, *sshpam_authok;
বাহ্য KbdintDevice sshpam_device;

পূর্ণাঙ্ক
mm_answer_pam_init_ctx(সংরচনা ssh *ssh, পূর্ণাঙ্ক sock, সংরচনা sshbuf *m)
{
	u_int ok = 0;
	পূর্ণাঙ্ক r;

	debug3_f("entering");
	যদি (!options.kbd_interactive_authentication)
		fatal_f("kbd-int authentication not enabled");
	যদি (sshpam_ctxt != রিক্ত)
		fatal_f("already called");
	sshpam_ctxt = (sshpam_device.init_ctx)(authctxt);
	sshpam_authok = রিক্ত;
	sshbuf_reset(m);
	যদি (sshpam_ctxt != রিক্ত) {
		monitor_permit(mon_dispatch, MONITOR_REQ_PAM_FREE_CTX, 1);
		monitor_permit(mon_dispatch, MONITOR_REQ_PAM_QUERY, 1);
		ok = 1;
	}
	যদি ((r = sshbuf_put_u32(m, ok)) != 0)
		fatal_fr(r, "buffer error");
	mm_request_send(sock, MONITOR_ANS_PAM_INIT_CTX, m);
	প্রত্যাগম (0);
}

পূর্ণাঙ্ক
mm_answer_pam_query(সংরচনা ssh *ssh, পূর্ণাঙ্ক sock, সংরচনা sshbuf *m)
{
	বর্ণ *name = রিক্ত, *info = রিক্ত, **prompts = রিক্ত;
	u_int i, অঙ্ক = 0, *echo_on = 0;
	পূর্ণাঙ্ক r, ret;

	debug3_f("entering");
	sshpam_authok = রিক্ত;
	যদি (sshpam_ctxt == রিক্ত)
		fatal_f("no context");
	ret = (sshpam_device.query)(sshpam_ctxt, &name, &info,
	    &অঙ্ক, &prompts, &echo_on);
	যদি (ret == 0 && অঙ্ক == 0 && sshpam_priv_kbdint_authdone(sshpam_ctxt))
		sshpam_authok = sshpam_ctxt;
	যদি (অঙ্ক > 1 || name == রিক্ত || info == রিক্ত)
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
	প্রতি (i = 0; i < অঙ্ক; ++i) {
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
	প্রত্যাগম (0);
}

পূর্ণাঙ্ক
mm_answer_pam_respond(সংরচনা ssh *ssh, পূর্ণাঙ্ক sock, সংরচনা sshbuf *m)
{
	বর্ণ **resp;
	u_int i, অঙ্ক;
	পূর্ণাঙ্ক r, ret;

	debug3_f("entering");
	যদি (sshpam_ctxt == রিক্ত)
		fatal_f("no context");
	sshpam_authok = রিক্ত;
	যদি ((r = sshbuf_get_u32(m, &অঙ্ক)) != 0)
		fatal_fr(r, "buffer error");
	যদি (অঙ্ক > PAM_MAX_অঙ্ক_বার্তা) {
		fatal_f("Too many PAM messages, got %u, expected <= %u",
		    অঙ্ক, (unsigned)PAM_MAX_অঙ্ক_বার্তা);
	}
	যদি (অঙ্ক > 0) {
		resp = xcalloc(অঙ্ক, পরিমাণ(বর্ণ *));
		প্রতি (i = 0; i < অঙ্ক; ++i) {
			যদি ((r = sshbuf_get_cstring(m, &(resp[i]), রিক্ত)) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
		}
		ret = (sshpam_device.respond)(sshpam_ctxt, অঙ্ক, resp);
		প্রতি (i = 0; i < অঙ্ক; ++i)
			মুক্ত(resp[i]);
		মুক্ত(resp);
	} অন্যথা {
		ret = (sshpam_device.respond)(sshpam_ctxt, অঙ্ক, রিক্ত);
	}
	sshbuf_reset(m);
	যদি ((r = sshbuf_put_u32(m, ret)) != 0)
		fatal_fr(r, "buffer error");
	mm_request_send(sock, MONITOR_ANS_PAM_RESPOND, m);
	auth_method = "keyboard-interactive";
	auth_submethod = "pam";
	যদি (ret == 0)
		sshpam_authok = sshpam_ctxt;
	প্রত্যাগম (0);
}

পূর্ণাঙ্ক
mm_answer_pam_free_ctx(সংরচনা ssh *ssh, পূর্ণাঙ্ক sock, সংরচনা sshbuf *m)
{
	পূর্ণাঙ্ক r = sshpam_authok != রিক্ত && sshpam_authok == sshpam_ctxt;

	debug3_f("entering");
	যদি (sshpam_ctxt == রিক্ত)
		fatal_f("no context");
	(sshpam_device.free_ctx)(sshpam_ctxt);
	sshpam_ctxt = sshpam_authok = রিক্ত;
	sshbuf_reset(m);
	mm_request_send(sock, MONITOR_ANS_PAM_FREE_CTX, m);
	/* Allow another attempt */
	monitor_permit(mon_dispatch, MONITOR_REQ_PAM_INIT_CTX, 1);
	auth_method = "keyboard-interactive";
	auth_submethod = "pam";
	প্রত্যাগম r;
}
#endif

পূর্ণাঙ্ক
mm_answer_keyallowed(সংরচনা ssh *ssh, পূর্ণাঙ্ক sock, সংরচনা sshbuf *m)
{
	সংরচনা sshkey *চাবি = রিক্ত;
	বর্ণ *cuser, *chost;
	u_int pubkey_auth_attempt;
	u_int type = 0;
	পূর্ণাঙ্ক r, allowed = 0;
	সংরচনা sshauthopt *opts = রিক্ত;

	debug3_f("entering");
	যদি ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_cstring(m, &cuser, রিক্ত)) != 0 ||
	    (r = sshbuf_get_cstring(m, &chost, রিক্ত)) != 0 ||
	    (r = sshkey_froms(m, &চাবি)) != 0 ||
	    (r = sshbuf_get_u32(m, &pubkey_auth_attempt)) != 0)
		fatal_fr(r, "parse");

	যদি (চাবি != রিক্ত && authctxt->valid) {
		বিকল্প (type) {
		পক্ষ MM_USERKEY:
			auth_method = "publickey";
			যদি (!options.pubkey_authentication)
				ভঙ্গ;
			যদি (auth2_চাবি_already_used(authctxt, চাবি))
				ভঙ্গ;
			যদি (!চাবি_base_type_match(auth_method, চাবি,
			    options.pubkey_accepted_algos))
				ভঙ্গ;
			allowed = user_চাবি_allowed(ssh, authctxt->pw, চাবি,
			    pubkey_auth_attempt, &opts);
			ভঙ্গ;
		পক্ষ MM_HOSTKEY:
			auth_method = "hostbased";
			যদি (!options.hostbased_authentication)
				ভঙ্গ;
			যদি (auth2_চাবি_already_used(authctxt, চাবি))
				ভঙ্গ;
			যদি (!চাবি_base_type_match(auth_method, চাবি,
			    options.hostbased_accepted_algos))
				ভঙ্গ;
			allowed = hostbased_চাবি_allowed(ssh, authctxt->pw,
			    cuser, chost, চাবি);
			auth2_record_info(authctxt,
			    "client user \"%.100s\", client host \"%.100s\"",
			    cuser, chost);
			ভঙ্গ;
		স্বভাব:
			fatal_f("unknown key type %u", type);
			ভঙ্গ;
		}
	}

	debug3_f("%s authentication%s: %s key is %s", auth_method,
	    pubkey_auth_attempt ? "" : " test",
	    (চাবি == রিক্ত || !authctxt->valid) ? "invalid" : sshkey_type(চাবি),
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
		auth_log(ssh, 0, 0, auth_method, রিক্ত);
		মুক্ত(cuser);
		মুক্ত(chost);
	}
	sshkey_free(চাবি);

	sshbuf_reset(m);
	যদি ((r = sshbuf_put_u32(m, allowed)) != 0)
		fatal_fr(r, "assemble");
	যদি (opts != রিক্ত && (r = sshauthopt_serialise(opts, m, 1)) != 0)
		fatal_fr(r, "sshauthopt_serialise");
	mm_request_send(sock, MONITOR_ANS_KEYALLOWED, m);

	যদি (!allowed)
		sshauthopt_free(opts);

	প্রত্যাগম (0);
}

স্থির পূর্ণাঙ্ক
monitor_valid_userblob(সংরচনা ssh *ssh, ধ্রুব u_char *data, u_int datalen)
{
	সংরচনা sshbuf *b;
	সংরচনা sshkey *hostkey = রিক্ত;
	ধ্রুব u_char *p;
	বর্ণ *userstyle, *cp;
	size_t len;
	u_char type;
	পূর্ণাঙ্ক hostbound = 0, r, fail = 0;

	যদি ((b = sshbuf_from(data, datalen)) == রিক্ত)
		fatal_f("sshbuf_from");

	যদি ((r = sshbuf_get_string_direct(b, &p, &len)) != 0)
		fatal_fr(r, "parse sessionid");
	যদি ((session_id2 == রিক্ত) ||
	    (len != session_id2_len) ||
	    (timingsafe_bcmp(p, session_id2, session_id2_len) != 0))
		fail++;
	যদি ((r = sshbuf_get_u8(b, &type)) != 0)
		fatal_fr(r, "parse type");
	যদি (type != SSH2_বার্তা_USERAUTH_REQUEST)
		fail++;
	যদি ((r = sshbuf_get_cstring(b, &cp, রিক্ত)) != 0)
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
	    (r = sshbuf_get_cstring(b, &cp, রিক্ত)) != 0)
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
	যদি (hostkey != রিক্ত) {
		/*
		 * Ensure this is actually one of our hostkeys; unfortunately
		 * can't check ssh->kex->initial_hostkey directly at this point
		 * as packet state has not yet been exported to monitor.
		 */
		যদি (get_hostkey_index(hostkey, 1, ssh) == -1)
			fatal_f("hostbound hostkey does not match");
		sshkey_free(hostkey);
	}
	প্রত্যাগম (fail == 0);
}

স্থির পূর্ণাঙ্ক
monitor_valid_hostbasedblob(ধ্রুব u_char *data, u_int datalen,
    ধ্রুব বর্ণ *cuser, ধ্রুব বর্ণ *chost)
{
	সংরচনা sshbuf *b;
	ধ্রুব u_char *p;
	বর্ণ *cp, *userstyle;
	size_t len;
	পূর্ণাঙ্ক r, fail = 0;
	u_char type;

	যদি ((b = sshbuf_from(data, datalen)) == রিক্ত)
		fatal_f("sshbuf_new");
	যদি ((r = sshbuf_get_string_direct(b, &p, &len)) != 0)
		fatal_fr(r, "parse sessionid");

	যদি ((session_id2 == রিক্ত) ||
	    (len != session_id2_len) ||
	    (timingsafe_bcmp(p, session_id2, session_id2_len) != 0))
		fail++;

	যদি ((r = sshbuf_get_u8(b, &type)) != 0)
		fatal_fr(r, "parse type");
	যদি (type != SSH2_বার্তা_USERAUTH_REQUEST)
		fail++;
	যদি ((r = sshbuf_get_cstring(b, &cp, রিক্ত)) != 0)
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
	    (r = sshbuf_get_cstring(b, &cp, রিক্ত)) != 0)
		fatal_fr(r, "parse method");
	যদি (strcmp(cp, "hostbased") != 0)
		fail++;
	মুক্ত(cp);
	যদি ((r = sshbuf_skip_string(b)) != 0 ||	/* pkalg */
	    (r = sshbuf_skip_string(b)) != 0)	/* pkblob */
		fatal_fr(r, "parse pk");

	/* verify client host, strip trailing dot if necessary */
	যদি ((r = sshbuf_get_cstring(b, &cp, রিক্ত)) != 0)
		fatal_fr(r, "parse host");
	যদি (((len = strlen(cp)) > 0) && cp[len - 1] == '.')
		cp[len - 1] = '\0';
	যদি (strcmp(cp, chost) != 0)
		fail++;
	মুক্ত(cp);

	/* verify client user */
	যদি ((r = sshbuf_get_cstring(b, &cp, রিক্ত)) != 0)
		fatal_fr(r, "parse ruser");
	যদি (strcmp(cp, cuser) != 0)
		fail++;
	মুক্ত(cp);

	যদি (sshbuf_len(b) != 0)
		fail++;
	sshbuf_free(b);
	প্রত্যাগম (fail == 0);
}

পূর্ণাঙ্ক
mm_answer_keyverify(সংরচনা ssh *ssh, পূর্ণাঙ্ক sock, সংরচনা sshbuf *m)
{
	সংরচনা sshkey *চাবি;
	ধ্রুব u_char *signature, *data, *blob;
	বর্ণ *sigalg = রিক্ত, *fp = রিক্ত;
	size_t signaturelen, datalen, bloblen;
	পূর্ণাঙ্ক r, ret, req_presence = 0, req_verify = 0, valid_data = 0;
	পূর্ণাঙ্ক encoded_ret;
	সংরচনা sshkey_sig_details *sig_details = রিক্ত;

	যদি ((r = sshbuf_get_string_direct(m, &blob, &bloblen)) != 0 ||
	    (r = sshbuf_get_string_direct(m, &signature, &signaturelen)) != 0 ||
	    (r = sshbuf_get_string_direct(m, &data, &datalen)) != 0 ||
	    (r = sshbuf_get_cstring(m, &sigalg, রিক্ত)) != 0)
		fatal_fr(r, "parse");

	যদি (hostbased_cuser == রিক্ত || hostbased_chost == রিক্ত ||
	  !monitor_allowed_চাবি(blob, bloblen))
		fatal_f("bad key, not previously allowed");

	/* Empty signature algorithm means NULL. */
	যদি (*sigalg == '\0') {
		মুক্ত(sigalg);
		sigalg = রিক্ত;
	}

	/* XXX use sshkey_froms here; need to change key_blob, etc. */
	যদি ((r = sshkey_from_blob(blob, bloblen, &চাবি)) != 0)
		fatal_fr(r, "parse key");

	বিকল্প (চাবি_blobtype) {
	পক্ষ MM_USERKEY:
		valid_data = monitor_valid_userblob(ssh, data, datalen);
		auth_method = "publickey";
		ভঙ্গ;
	পক্ষ MM_HOSTKEY:
		valid_data = monitor_valid_hostbasedblob(data, datalen,
		    hostbased_cuser, hostbased_chost);
		auth_method = "hostbased";
		ভঙ্গ;
	স্বভাব:
		valid_data = 0;
		ভঙ্গ;
	}
	যদি (!valid_data)
		fatal_f("bad %s signature data blob",
		    চাবি_blobtype == MM_USERKEY ? "userkey" :
		    (চাবি_blobtype == MM_HOSTKEY ? "hostkey" : "unknown"));

	যদি ((fp = sshkey_fingerprint(চাবি, options.fingerprint_hash,
	    SSH_FP_DEFAULT)) == রিক্ত)
		fatal_f("sshkey_fingerprint failed");

	ret = sshkey_verify(চাবি, signature, signaturelen, data, datalen,
	    sigalg, ssh->compat, &sig_details);
	debug3_f("%s %s signature using %s %s%s%s", auth_method,
	    sshkey_type(চাবি), sigalg == রিক্ত ? "default" : sigalg,
	    (ret == 0) ? "verified" : "unverified",
	    (ret != 0) ? ": " : "", (ret != 0) ? ssh_err(ret) : "");

	যদি (ret == 0 && চাবি_blobtype == MM_USERKEY && sig_details != রিক্ত) {
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
	    (r = sshbuf_put_u8(m, sig_details != রিক্ত)) != 0)
		fatal_fr(r, "assemble");
	যদি (sig_details != রিক্ত) {
		যদি ((r = sshbuf_put_u32(m, sig_details->sk_counter)) != 0 ||
		    (r = sshbuf_put_u8(m, sig_details->sk_flags)) != 0)
			fatal_fr(r, "assemble sk");
	}
	sshkey_sig_details_free(sig_details);
	mm_request_send(sock, MONITOR_ANS_KEYVERIFY, m);

	মুক্ত(sigalg);
	মুক্ত(fp);
	sshkey_free(চাবি);

	প্রত্যাগম ret == 0;
}

স্থির শূন্য
mm_record_login(সংরচনা ssh *ssh, Session *s, সংরচনা passwd *pw)
{
	socklen_t fromlen;
	সংরচনা sockaddr_storage from;

	/*
	 * Get IP address of client. If the connection is not a socket, let
	 * the address be 0.0.0.0.
	 */
	memset(&from, 0, পরিমাণ(from));
	fromlen = পরিমাণ(from);
	যদি (ssh_packet_connection_is_on_socket(ssh)) {
		যদি (getpeername(ssh_packet_get_connection_in(ssh),
		    (সংরচনা sockaddr *)&from, &fromlen) == -1) {
			debug("getpeername: %.100s", strerror(errno));
			cleanup_exit(255);
		}
	}
	/* Record that there was a login on that tty from the remote host. */
	record_login(s->pid, s->tty, pw->pw_name, pw->pw_uid,
	    session_get_remote_name_or_ip(ssh, utmp_len, options.use_dns),
	    (সংরচনা sockaddr *)&from, fromlen);
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

পূর্ণাঙ্ক
mm_answer_pty(সংরচনা ssh *ssh, পূর্ণাঙ্ক sock, সংরচনা sshbuf *m)
{
	বাহ্য সংরচনা monitor *pmonitor;
	Session *s;
	পূর্ণাঙ্ক r, res, fd0;

	debug3_f("entering");

	sshbuf_reset(m);
	s = session_new();
	যদি (s == রিক্ত)
		গচ্ছ error;
	s->authctxt = authctxt;
	s->pw = authctxt->pw;
	s->pid = pmonitor->m_pid;
	res = pty_allocate(&s->ptyfd, &s->ttyfd, s->tty, পরিমাণ(s->tty));
	যদি (res == 0)
		গচ্ছ error;
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

	প্রত্যাগম (0);

 error:
	যদি (s != রিক্ত)
		mm_session_close(s);
	যদি ((r = sshbuf_put_u32(m, 0)) != 0)
		fatal_fr(r, "assemble 0");
	mm_request_send(sock, MONITOR_ANS_PTY, m);
	প্রত্যাগম (0);
}

পূর্ণাঙ্ক
mm_answer_pty_cleanup(সংরচনা ssh *ssh, পূর্ণাঙ্ক sock, সংরচনা sshbuf *m)
{
	Session *s;
	বর্ণ *tty;
	পূর্ণাঙ্ক r;

	debug3_f("entering");

	যদি ((r = sshbuf_get_cstring(m, &tty, রিক্ত)) != 0)
		fatal_fr(r, "parse tty");
	যদি ((s = session_by_tty(tty)) != রিক্ত)
		mm_session_close(s);
	sshbuf_reset(m);
	মুক্ত(tty);
	প্রত্যাগম (0);
}

পূর্ণাঙ্ক
mm_answer_term(সংরচনা ssh *ssh, পূর্ণাঙ্ক sock, সংরচনা sshbuf *req)
{
	বাহ্য সংরচনা monitor *pmonitor;
	পূর্ণাঙ্ক res, status;

	debug3_f("tearing down sessions");

	/* The child is terminating */
	session_destroy_all(ssh, &mm_session_close);

#ifdef USE_PAM
	যদি (options.use_pam)
		sshpam_cleanup();
#endif

	যাবত্ (waitpid(pmonitor->m_pid, &status, 0) == -1)
		যদি (errno != EINTR)
			exit(1);

	res = WIFEXITED(status) ? WEXITSTATUS(status) : 1;

	/* Terminate process */
	exit(res);
}

#ifdef SSH_AUDIT_EVENTS
/* Report that an audit event occurred */
পূর্ণাঙ্ক
mm_answer_audit_event(সংরচনা ssh *ssh, পূর্ণাঙ্ক socket, সংরচনা sshbuf *m)
{
	u_int n;
	ssh_audit_event_t event;
	পূর্ণাঙ্ক r;

	debug3_f("entering");

	যদি ((r = sshbuf_get_u32(m, &n)) != 0)
		fatal_fr(r, "buffer error");
	event = (ssh_audit_event_t)n;
	বিকল্প (event) {
	পক্ষ SSH_AUTH_FAIL_PUBKEY:
	পক্ষ SSH_AUTH_FAIL_HOSTBASED:
	পক্ষ SSH_AUTH_FAIL_GSSAPI:
	পক্ষ SSH_LOGIN_EXCEED_MAXTRIES:
	পক্ষ SSH_LOGIN_মূল_DENIED:
	পক্ষ SSH_CONNECTION_CLOSE:
	পক্ষ SSH_INVALID_USER:
		audit_event(ssh, event);
		ভঙ্গ;
	স্বভাব:
		fatal("Audit event type %d not permitted", event);
	}

	প্রত্যাগম (0);
}

পূর্ণাঙ্ক
mm_answer_audit_command(সংরচনা ssh *ssh, পূর্ণাঙ্ক socket, সংরচনা sshbuf *m)
{
	বর্ণ *cmd;
	পূর্ণাঙ্ক r;

	debug3_f("entering");
	যদি ((r = sshbuf_get_cstring(m, &cmd, রিক্ত)) != 0)
		fatal_fr(r, "buffer error");
	/* sanity check command, if so how? */
	audit_run_command(cmd);
	মুক্ত(cmd);
	প্রত্যাগম (0);
}
#endif /* SSH_AUDIT_EVENTS */

শূন্য
monitor_clear_keystate(সংরচনা ssh *ssh, সংরচনা monitor *pmonitor)
{
	ssh_clear_newkeys(ssh, MODE_IN);
	ssh_clear_newkeys(ssh, MODE_OUT);
	sshbuf_free(child_state);
	child_state = রিক্ত;
}

শূন্য
monitor_apply_keystate(সংরচনা ssh *ssh, সংরচনা monitor *pmonitor)
{
	সংরচনা kex *kex;
	পূর্ণাঙ্ক r;

	debug3_f("packet_set_state");
	যদি ((r = ssh_packet_set_state(ssh, child_state)) != 0)
		fatal_fr(r, "packet_set_state");
	sshbuf_free(child_state);
	child_state = রিক্ত;
	যদি ((kex = ssh->kex) == রিক্ত)
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
	kex->host_চাবি_index=&get_hostkey_index;
	kex->sign = sshd_hostkey_sign;
}

/* This function requires careful sanity checking */

শূন্য
mm_get_keystate(সংরচনা ssh *ssh, সংরচনা monitor *pmonitor)
{
	debug3_f("Waiting for new keys");

	যদি ((child_state = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new failed");
	mm_request_receive_expect(pmonitor->m_sendfd, MONITOR_REQ_KEYEXPORT,
	    child_state);
	debug3_f("GOT new keys");
}


/* XXX */

স্থির শূন্য
monitor_openfds(সংরচনা monitor *mon, পূর্ণাঙ্ক do_logfds)
{
	পূর্ণাঙ্ক pair[2];
#ifdef SO_ZEROIZE
	পূর্ণাঙ্ক on = 1;
#endif

	যদি (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == -1)
		fatal_f("socketpair: %s", strerror(errno));
#ifdef SO_ZEROIZE
	যদি (setsockopt(pair[0], SOL_SOCKET, SO_ZEROIZE, &on, পরিমাণ(on)) == -1)
		error("setsockopt SO_ZEROIZE(0): %.100s", strerror(errno));
	যদি (setsockopt(pair[1], SOL_SOCKET, SO_ZEROIZE, &on, পরিমাণ(on)) == -1)
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

সংরচনা monitor *
monitor_init(শূন্য)
{
	সংরচনা monitor *mon;

	mon = xcalloc(1, পরিমাণ(*mon));
	monitor_openfds(mon, 1);

	প্রত্যাগম mon;
}

শূন্য
monitor_reinit(সংরচনা monitor *mon)
{
	monitor_openfds(mon, 0);
}

পূর্ণাঙ্ক
monitor_auth_attempted(শূন্য)
{
	প্রত্যাগম auth_attempted;
}

পূর্ণাঙ্ক
monitor_invalid_user(শূন্য)
{
	প্রত্যাগম invalid_user;
}

#ifdef GSSAPI
পূর্ণাঙ্ক
mm_answer_gss_setup_ctx(সংরচনা ssh *ssh, পূর্ণাঙ্ক sock, সংরচনা sshbuf *m)
{
	gss_OID_desc goid;
	OM_uint32 major;
	size_t len;
	u_char *p;
	পূর্ণাঙ্ক r;

	যদি (!options.gss_authentication)
		fatal_f("GSSAPI authentication not enabled");

	ssh_gssapi_cleanup_global_client();

	যদি ((r = sshbuf_get_string(m, &p, &len)) != 0)
		fatal_fr(r, "parse");
	goid.elements = p;
	goid.length = len;

	major = ssh_gssapi_server_ctx(&gsscontext, &goid);

	মুক্ত(goid.elements);

	sshbuf_reset(m);
	যদি ((r = sshbuf_put_u32(m, major)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(sock, MONITOR_ANS_GSSSETUP, m);

	/* Now we have a context, enable the step */
	monitor_permit(mon_dispatch, MONITOR_REQ_GSSSTEP, 1);

	প্রত্যাগম (0);
}

পূর্ণাঙ্ক
mm_answer_gss_accept_ctx(সংরচনা ssh *ssh, পূর্ণাঙ্ক sock, সংরচনা sshbuf *m)
{
	gss_buffer_desc in;
	gss_buffer_desc out = GSS_C_EMPTY_BUFFER;
	OM_uint32 major, minor;
	OM_uint32 flags = 0; /* GSI needs this */
	পূর্ণাঙ্ক r;

	যদি (!options.gss_authentication)
		fatal_f("GSSAPI authentication not enabled");

	যদি ((r = ssh_gssapi_get_buffer_desc(m, &in)) != 0)
		fatal_fr(r, "ssh_gssapi_get_buffer_desc");
	major = ssh_gssapi_accept_ctx(gsscontext, &in, &out, &flags);
	মুক্ত(in.মান);

	sshbuf_reset(m);
	যদি ((r = sshbuf_put_u32(m, major)) != 0 ||
	    (r = sshbuf_put_string(m, out.মান, out.length)) != 0 ||
	    (r = sshbuf_put_u32(m, flags)) != 0)
		fatal_fr(r, "assemble");
	mm_request_send(sock, MONITOR_ANS_GSSSTEP, m);

	gss_release_buffer(&minor, &out);

	যদি (major == GSS_S_COMPLETE) {
		monitor_permit(mon_dispatch, MONITOR_REQ_GSSSTEP, 0);
		monitor_permit(mon_dispatch, MONITOR_REQ_GSSUSEROK, 1);
		monitor_permit(mon_dispatch, MONITOR_REQ_GSSCHECKMIC, 1);
	}
	প্রত্যাগম (0);
}

পূর্ণাঙ্ক
mm_answer_gss_checkmic(সংরচনা ssh *ssh, পূর্ণাঙ্ক sock, সংরচনা sshbuf *m)
{
	gss_buffer_desc gssbuf, mic;
	OM_uint32 ret;
	পূর্ণাঙ্ক r;

	যদি (!options.gss_authentication)
		fatal_f("GSSAPI authentication not enabled");

	যদি ((r = ssh_gssapi_get_buffer_desc(m, &gssbuf)) != 0 ||
	    (r = ssh_gssapi_get_buffer_desc(m, &mic)) != 0)
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

	প্রত্যাগম (0);
}

পূর্ণাঙ্ক
mm_answer_gss_userok(সংরচনা ssh *ssh, পূর্ণাঙ্ক sock, সংরচনা sshbuf *m)
{
	পূর্ণাঙ্ক r, authenticated;
	ধ্রুব বর্ণ *displayname;

	যদি (!options.gss_authentication)
		fatal_f("GSSAPI authentication not enabled");

	authenticated = authctxt->valid && ssh_gssapi_userok(authctxt->user);

	sshbuf_reset(m);
	যদি ((r = sshbuf_put_u32(m, authenticated)) != 0)
		fatal_fr(r, "assemble");

	debug3_f("sending result %d", authenticated);
	mm_request_send(sock, MONITOR_ANS_GSSUSEROK, m);

	auth_method = "gssapi-with-mic";

	যদি ((displayname = ssh_gssapi_displayname()) != রিক্ত)
		auth2_record_info(authctxt, "%s", displayname);

	/* Monitor loop will terminate if authenticated */
	প্রত্যাগম (authenticated);
}
#endif /* GSSAPI */

