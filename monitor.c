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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <sys/wait.h>
#అన్తర్భావ <sys/socket.h>
#అన్తర్భావ <sys/tree.h>
#అన్తర్భావ <sys/queue.h>

#అన్తర్భావ <errno.h>
#అన్తర్భావ <fcntl.h>
#అన్తర్భావ <limits.h>
#అన్తర్భావ <paths.h>
#అన్తర్భావ <poll.h>
#అన్తర్భావ <pwd.h>
#అన్తర్భావ <signal.h>
#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <stdint.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <unistd.h>

#నిర్వచితమైతే WITH_OPENSSL
#అన్తర్భావ <openssl/dh.h>
#అయితే_ముగింపు

#అన్తర్భావ "openbsd-compat/openssl-compat.h"

#అన్తర్భావ "atomicio.h"
#అన్తర్భావ "xmalloc.h"
#అన్తర్భావ "ssh.h"
#అన్తర్భావ "sshkey.h"
#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "hostfile.h"
#అన్తర్భావ "auth.h"
#అన్తర్భావ "cipher.h"
#అన్తర్భావ "kex.h"
#అన్తర్భావ "dh.h"
#అన్తర్భావ "auth-pam.h"
#అన్తర్భావ "packet.h"
#అన్తర్భావ "auth-options.h"
#అన్తర్భావ "sshpty.h"
#అన్తర్భావ "channels.h"
#అన్తర్భావ "session.h"
#అన్తర్భావ "sshlogin.h"
#అన్తర్భావ "canohost.h"
#అన్తర్భావ "log.h"
#అన్తర్భావ "misc.h"
#అన్తర్భావ "servconf.h"
#అన్తర్భావ "monitor.h"
#నిర్వచితమైతే GSSAPI
#అన్తర్భావ "ssh-gss.h"
#అయితే_ముగింపు
#అన్తర్భావ "monitor_wrap.h"
#అన్తర్భావ "monitor_fdpass.h"
#అన్తర్భావ "compat.h"
#అన్తర్భావ "ssh2.h"
#అన్తర్భావ "authfd.h"
#అన్తర్భావ "match.h"
#అన్తర్భావ "ssherr.h"
#అన్తర్భావ "sk-api.h"
#అన్తర్భావ "srclimit.h"

#నిర్వచితమైతే GSSAPI
స్థిర Gssctxt *gsscontext = ఖాళీ;
#అయితే_ముగింపు

/* Imports */
బాహ్య ServerOptions options;
బాహ్య u_int utmp_len;
బాహ్య నిర్మాణం sshbuf *cfg;
బాహ్య నిర్మాణం sshbuf *loginmsg;
బాహ్య నిర్మాణం include_list includes;
బాహ్య నిర్మాణం sshauthopt *auth_opts; /* XXX move to permanent ssh->authctxt? */

/* State exported from the child */
స్థిర నిర్మాణం sshbuf *బిడ్డ_state;

/* Functions on the monitor that answer unprivileged requests */

పూర్ణాంకం mm_answer_moduli(నిర్మాణం ssh *, పూర్ణాంకం, నిర్మాణం sshbuf *);
పూర్ణాంకం mm_answer_setcompat(నిర్మాణం ssh *, పూర్ణాంకం, నిర్మాణం sshbuf *);
పూర్ణాంకం mm_answer_sign(నిర్మాణం ssh *, పూర్ణాంకం, నిర్మాణం sshbuf *);
పూర్ణాంకం mm_answer_pwnamallow(నిర్మాణం ssh *, పూర్ణాంకం, నిర్మాణం sshbuf *);
పూర్ణాంకం mm_answer_auth2_read_banner(నిర్మాణం ssh *, పూర్ణాంకం, నిర్మాణం sshbuf *);
పూర్ణాంకం mm_answer_authserv(నిర్మాణం ssh *, పూర్ణాంకం, నిర్మాణం sshbuf *);
పూర్ణాంకం mm_answer_authpassword(నిర్మాణం ssh *, పూర్ణాంకం, నిర్మాణం sshbuf *);
పూర్ణాంకం mm_answer_bsdauthquery(నిర్మాణం ssh *, పూర్ణాంకం, నిర్మాణం sshbuf *);
పూర్ణాంకం mm_answer_bsdauthrespond(నిర్మాణం ssh *, పూర్ణాంకం, నిర్మాణం sshbuf *);
పూర్ణాంకం mm_answer_keyallowed(నిర్మాణం ssh *, పూర్ణాంకం, నిర్మాణం sshbuf *);
పూర్ణాంకం mm_answer_keyverify(నిర్మాణం ssh *, పూర్ణాంకం, నిర్మాణం sshbuf *);
పూర్ణాంకం mm_answer_pty(నిర్మాణం ssh *, పూర్ణాంకం, నిర్మాణం sshbuf *);
పూర్ణాంకం mm_answer_pty_cleanup(నిర్మాణం ssh *, పూర్ణాంకం, నిర్మాణం sshbuf *);
పూర్ణాంకం mm_answer_పదం(నిర్మాణం ssh *, పూర్ణాంకం, నిర్మాణం sshbuf *);
పూర్ణాంకం mm_answer_state(నిర్మాణం ssh *, పూర్ణాంకం, నిర్మాణం sshbuf *);

#నిర్వచితమైతే USE_PAM
పూర్ణాంకం mm_answer_pam_ప్రారంభం(నిర్మాణం ssh *, పూర్ణాంకం, నిర్మాణం sshbuf *);
పూర్ణాంకం mm_answer_pam_account(నిర్మాణం ssh *, పూర్ణాంకం, నిర్మాణం sshbuf *);
పూర్ణాంకం mm_answer_pam_init_ctx(నిర్మాణం ssh *, పూర్ణాంకం, నిర్మాణం sshbuf *);
పూర్ణాంకం mm_answer_pam_query(నిర్మాణం ssh *, పూర్ణాంకం, నిర్మాణం sshbuf *);
పూర్ణాంకం mm_answer_pam_respond(నిర్మాణం ssh *, పూర్ణాంకం, నిర్మాణం sshbuf *);
పూర్ణాంకం mm_answer_pam_free_ctx(నిర్మాణం ssh *, పూర్ణాంకం, నిర్మాణం sshbuf *);
#అయితే_ముగింపు

#నిర్వచితమైతే GSSAPI
పూర్ణాంకం mm_answer_gss_అమరిక_ctx(నిర్మాణం ssh *, పూర్ణాంకం, నిర్మాణం sshbuf *);
పూర్ణాంకం mm_answer_gss_accept_ctx(నిర్మాణం ssh *, పూర్ణాంకం, నిర్మాణం sshbuf *);
పూర్ణాంకం mm_answer_gss_userok(నిర్మాణం ssh *, పూర్ణాంకం, నిర్మాణం sshbuf *);
పూర్ణాంకం mm_answer_gss_checkmic(నిర్మాణం ssh *, పూర్ణాంకం, నిర్మాణం sshbuf *);
#అయితే_ముగింపు

#నిర్వచితమైతే SSH_AUDIT_EVENTS
పూర్ణాంకం mm_answer_audit_event(నిర్మాణం ssh *, పూర్ణాంకం, నిర్మాణం sshbuf *);
పూర్ణాంకం mm_answer_audit_command(నిర్మాణం ssh *, పూర్ణాంకం, నిర్మాణం sshbuf *);
#అయితే_ముగింపు

స్థిర Authctxt *authctxt;

/* local state for key verify */
స్థిర u_char *కీలకం_blob = ఖాళీ;
స్థిర కొలత_t కీలకం_bloblen = 0;
స్థిర u_int కీలకం_blobtype = MM_NOKEY;
స్థిర నిర్మాణం sshauthopt *కీలకం_opts = ఖాళీ;
స్థిర అక్షరం *hostbased_cuser = ఖాళీ;
స్థిర అక్షరం *hostbased_chost = ఖాళీ;
స్థిర అక్షరం *auth_పద్ధతి = "unknown";
స్థిర అక్షరం *auth_submethod = ఖాళీ;
స్థిర u_int session_id2_len = 0;
స్థిర u_char *session_id2 = ఖాళీ;
స్థిర pid_t monitor_బిడ్డ_pid;
స్థిర పూర్ణాంకం auth_attempted = 0;
స్థిర పూర్ణాంకం invalid_user = 0;
స్థిర పూర్ణాంకం compat_సమితి = 0;

నిర్మాణం mon_పట్టిక {
	గణన monitor_reqtype type;
	పూర్ణాంకం flags;
	పూర్ణాంకం (*f)(నిర్మాణం ssh *, పూర్ణాంకం, నిర్మాణం sshbuf *);
};

#నిర్వచించు MON_ISAUTH	0x0004	/* Required for Authentication */
#నిర్వచించు MON_AUTHDECIDE	0x0008	/* Decides Authentication */
#నిర్వచించు MON_ONCE	0x0010	/* Disable after calling */
#నిర్వచించు MON_ALOG	0x0020	/* Log auth attempt without authenticating */

#నిర్వచించు MON_AUTH	(MON_ISAUTH|MON_AUTHDECIDE)

#నిర్వచించు MON_PERMIT	0x1000	/* Request is permitted */

స్థిర పూర్ణాంకం monitor_read(నిర్మాణం ssh *, నిర్మాణం monitor *, నిర్మాణం mon_పట్టిక *,
    నిర్మాణం mon_పట్టిక **);
స్థిర పూర్ణాంకం monitor_read_log(నిర్మాణం monitor *);

నిర్మాణం mon_పట్టిక mon_dispatch_proto20[] = {
    {MONITOR_REQ_STATE, MON_ONCE, mm_answer_state},
#నిర్వచితమైతే WITH_OPENSSL
    {MONITOR_REQ_MODULI, MON_ONCE, mm_answer_moduli},
#అయితే_ముగింపు
    {MONITOR_REQ_SETCOMPAT, MON_ONCE, mm_answer_setcompat},
    {MONITOR_REQ_SIGN, MON_ONCE, mm_answer_sign},
    {MONITOR_REQ_PWNAM, MON_ONCE, mm_answer_pwnamallow},
    {MONITOR_REQ_AUTHSERV, MON_ONCE, mm_answer_authserv},
    {MONITOR_REQ_AUTH2_READ_BANNER, MON_ONCE, mm_answer_auth2_read_banner},
    {MONITOR_REQ_AUTHPASSWORD, MON_AUTH, mm_answer_authpassword},
#నిర్వచితమైతే USE_PAM
    {MONITOR_REQ_PAM_ప్రారంభం, MON_ONCE, mm_answer_pam_ప్రారంభం},
    {MONITOR_REQ_PAM_ACCOUNT, 0, mm_answer_pam_account},
    {MONITOR_REQ_PAM_INIT_CTX, MON_ONCE, mm_answer_pam_init_ctx},
    {MONITOR_REQ_PAM_QUERY, 0, mm_answer_pam_query},
    {MONITOR_REQ_PAM_RESPOND, MON_ONCE, mm_answer_pam_respond},
    {MONITOR_REQ_PAM_FREE_CTX, MON_ONCE|MON_AUTHDECIDE, mm_answer_pam_free_ctx},
#అయితే_ముగింపు
#నిర్వచితమైతే SSH_AUDIT_EVENTS
    {MONITOR_REQ_AUDIT_EVENT, MON_PERMIT, mm_answer_audit_event},
#అయితే_ముగింపు
#నిర్వచితమైతే BSD_AUTH
    {MONITOR_REQ_BSDAUTHQUERY, MON_ISAUTH, mm_answer_bsdauthquery},
    {MONITOR_REQ_BSDAUTHRESPOND, MON_AUTH, mm_answer_bsdauthrespond},
#అయితే_ముగింపు
    {MONITOR_REQ_KEYALLOWED, MON_ISAUTH, mm_answer_keyallowed},
    {MONITOR_REQ_KEYVERIFY, MON_AUTH, mm_answer_keyverify},
#నిర్వచితమైతే GSSAPI
    {MONITOR_REQ_GSSSETUP, MON_ISAUTH, mm_answer_gss_అమరిక_ctx},
    {MONITOR_REQ_GSSSTEP, 0, mm_answer_gss_accept_ctx},
    {MONITOR_REQ_GSSUSEROK, MON_ONCE|MON_AUTHDECIDE, mm_answer_gss_userok},
    {MONITOR_REQ_GSSCHECKMIC, MON_ONCE, mm_answer_gss_checkmic},
#అయితే_ముగింపు
    {0, 0, ఖాళీ}
};

నిర్మాణం mon_పట్టిక mon_dispatch_postauth20[] = {
    {MONITOR_REQ_STATE, MON_ONCE, mm_answer_state},
#నిర్వచితమైతే WITH_OPENSSL
    {MONITOR_REQ_MODULI, 0, mm_answer_moduli},
#అయితే_ముగింపు
    {MONITOR_REQ_SIGN, 0, mm_answer_sign},
    {MONITOR_REQ_PTY, 0, mm_answer_pty},
    {MONITOR_REQ_PTYCLEANUP, 0, mm_answer_pty_cleanup},
    {MONITOR_REQ_పదం, 0, mm_answer_పదం},
#నిర్వచితమైతే SSH_AUDIT_EVENTS
    {MONITOR_REQ_AUDIT_EVENT, MON_PERMIT, mm_answer_audit_event},
    {MONITOR_REQ_AUDIT_COMMAND, MON_PERMIT, mm_answer_audit_command},
#అయితే_ముగింపు
    {0, 0, ఖాళీ}
};

నిర్మాణం mon_పట్టిక *mon_dispatch;

/* Specifies if a certain message is allowed at the moment */
స్థిర శూన్య
monitor_permit(నిర్మాణం mon_పట్టిక *ent, గణన monitor_reqtype type, పూర్ణాంకం permit)
{
	అయితే (ent->f != ఖాళీ) {
		ఒకవేళ (ent->type == type) {
			ent->flags &= ~MON_PERMIT;
			ent->flags |= permit ? MON_PERMIT : 0;
			తిరిగి;
		}
		ent++;
	}
}

స్థిర శూన్య
monitor_permit_authentications(పూర్ణాంకం permit)
{
	నిర్మాణం mon_పట్టిక *ent = mon_dispatch;

	అయితే (ent->f != ఖాళీ) {
		ఒకవేళ (ent->flags & MON_AUTH) {
			ent->flags &= ~MON_PERMIT;
			ent->flags |= permit ? MON_PERMIT : 0;
		}
		ent++;
	}
}

శూన్య
monitor_బిడ్డ_preauth(నిర్మాణం ssh *ssh, నిర్మాణం monitor *pmonitor)
{
	నిర్మాణం mon_పట్టిక *ent;
	పూర్ణాంకం స్థితి_2, authenticated = 0, partial = 0;

	debug3("preauth child monitor started");

	ఒకవేళ (pmonitor->m_recvfd >= 0)
		close(pmonitor->m_recvfd);
	ఒకవేళ (pmonitor->m_log_sendfd >= 0)
		close(pmonitor->m_log_sendfd);
	pmonitor->m_log_sendfd = pmonitor->m_recvfd = -1;

	authctxt = (Authctxt *)ssh->authctxt;
	memset(authctxt, 0, పరిమాణం(*authctxt));
	ssh->authctxt = authctxt;

	authctxt->loginmsg = loginmsg;

	mon_dispatch = mon_dispatch_proto20;
	/* Permit requests for state, moduli and signatures */
	monitor_permit(mon_dispatch, MONITOR_REQ_STATE, 1);
	monitor_permit(mon_dispatch, MONITOR_REQ_MODULI, 1);
	monitor_permit(mon_dispatch, MONITOR_REQ_SETCOMPAT, 1);
	monitor_permit(mon_dispatch, MONITOR_REQ_SIGN, 1);

	/* The first few requests do not require asynchronous access */
	అయితే (!authenticated) {
		partial = 0;
		auth_పద్ధతి = "unknown";
		auth_submethod = ఖాళీ;
		auth2_authctxt_reset_info(authctxt);

		authenticated = (monitor_read(ssh, pmonitor,
		    mon_dispatch, &ent) == 1);

		/* Record that auth was attempted to set exit status later */
		ఒకవేళ ((ent->flags & MON_AUTH) != 0)
			auth_attempted = 1;

		/* Special handling for multiple required authentications */
		ఒకవేళ (options.అంకె_auth_methods != 0) {
			ఒకవేళ (authenticated &&
			    !auth2_update_methods_lists(authctxt,
			    auth_పద్ధతి, auth_submethod)) {
				debug3_f("method %s: partial", auth_పద్ధతి);
				authenticated = 0;
				partial = 1;
			}
		}

		ఒకవేళ (authenticated) {
			ఒకవేళ (!(ent->flags & MON_AUTHDECIDE))
				fatal_f("unexpected authentication from %d",
				    ent->type);
			ఒకవేళ (authctxt->pw->pw_uid == 0 &&
			    !auth_మూలం_allowed(ssh, auth_పద్ధతి))
				authenticated = 0;
#నిర్వచితమైతే USE_PAM
			/* PAM needs to perform account checks after auth */
			ఒకవేళ (options.use_pam && authenticated) {
				నిర్మాణం sshbuf *m;

				ఒకవేళ ((m = sshbuf_new()) == ఖాళీ)
					fatal("%s: sshbuf_new failed",
					    __func__);
				mm_request_receive_expect(pmonitor->m_sendfd,
				    MONITOR_REQ_PAM_ACCOUNT, m);
				authenticated = mm_answer_pam_account(
				    ssh, pmonitor->m_sendfd, m);
				sshbuf_free(m);
			}
#అయితే_ముగింపు
		}
		ఒకవేళ (ent->flags & (MON_AUTHDECIDE|MON_ALOG)) {
			auth_log(ssh, authenticated, partial,
			    auth_పద్ధతి, auth_submethod);
			ఒకవేళ (!partial && !authenticated)
				authctxt->failures++;
			ఒకవేళ (authenticated || partial) {
				auth2_update_session_info(authctxt,
				    auth_పద్ధతి, auth_submethod);
			}
		}
		ఒకవేళ (authctxt->failures > options.max_authtries) {
			/* Shouldn't happen */
			fatal_f("privsep child made too many authentication "
			    "attempts");
		}
	}

	ఒకవేళ (!authctxt->valid)
		fatal_f("authenticated invalid user");
	ఒకవేళ (strcmp(auth_పద్ధతి, "unknown") == 0)
		fatal_f("authentication method name unknown");

	debug_f("user %s authenticated by privileged process", authctxt->user);
	auth_attempted = 0;
	ssh->authctxt = ఖాళీ;
	ssh_packet_సమితి_log_preamble(ssh, "user %s", authctxt->user);

	mm_get_keystate(ssh, pmonitor);

	/* Drain any buffered messages from the child */
	అయితే (pmonitor->m_log_recvfd != -1 && monitor_read_log(pmonitor) == 0)
		;

	/* Wait for the child's exit status */
	అయితే (waitpid(pmonitor->m_pid, &స్థితి_2, 0) == -1) {
		ఒకవేళ (errno == EINTR)
			కొనసాగు;
		fatal_f("waitpid: %s", strerror(errno));
	}
	ఒకవేళ (WIFEXITED(స్థితి_2)) {
		ఒకవేళ (WEXITSTATUS(స్థితి_2) != 0)
			fatal_f("preauth child %ld exited with status %d",
			    (దీర్ఘ)pmonitor->m_pid, WEXITSTATUS(స్థితి_2));
	} లేకపోతే ఒకవేళ (WIFSIGNALED(స్థితి_2)) {
		fatal_f("preauth child %ld terminated by signal %d",
		    (దీర్ఘ)pmonitor->m_pid, WTERMSIG(స్థితి_2));
	}
	debug3_f("preauth child %ld terminated successfully",
	    (దీర్ఘ)pmonitor->m_pid);

	ఒకవేళ (pmonitor->m_recvfd >= 0)
		close(pmonitor->m_recvfd);
	ఒకవేళ (pmonitor->m_log_sendfd >= 0)
		close(pmonitor->m_log_sendfd);
	pmonitor->m_sendfd = pmonitor->m_log_recvfd = -1;
	pmonitor->m_pid = -1;
}

స్థిర శూన్య
monitor_సమితి_బిడ్డ_handler(pid_t pid)
{
	monitor_బిడ్డ_pid = pid;
}

స్థిర శూన్య
monitor_బిడ్డ_handler(పూర్ణాంకం sig)
{
	kill(monitor_బిడ్డ_pid, sig);
}

శూన్య
monitor_బిడ్డ_postauth(నిర్మాణం ssh *ssh, నిర్మాణం monitor *pmonitor)
{
	close(pmonitor->m_recvfd);
	pmonitor->m_recvfd = -1;

	monitor_సమితి_బిడ్డ_handler(pmonitor->m_pid);
	ssh_signal(SIGHUP, &monitor_బిడ్డ_handler);
	ssh_signal(SIGTERM, &monitor_బిడ్డ_handler);
	ssh_signal(SIGINT, &monitor_బిడ్డ_handler);
#నిర్వచితమైతే SIGXFSZ
	ssh_signal(SIGXFSZ, SIG_IGN);
#అయితే_ముగింపు

	mon_dispatch = mon_dispatch_postauth20;

	/* Permit requests for moduli and signatures */
	monitor_permit(mon_dispatch, MONITOR_REQ_STATE, 1);
	monitor_permit(mon_dispatch, MONITOR_REQ_MODULI, 1);
	monitor_permit(mon_dispatch, MONITOR_REQ_SIGN, 1);
	monitor_permit(mon_dispatch, MONITOR_REQ_పదం, 1);

	ఒకవేళ (auth_opts->permit_pty_flag) {
		monitor_permit(mon_dispatch, MONITOR_REQ_PTY, 1);
		monitor_permit(mon_dispatch, MONITOR_REQ_PTYCLEANUP, 1);
	}

	కొరకు (;;)
		monitor_read(ssh, pmonitor, mon_dispatch, ఖాళీ);
}

స్థిర పూర్ణాంకం
monitor_read_log(నిర్మాణం monitor *pmonitor)
{
	నిర్మాణం sshbuf *logmsg;
	u_int len, level, forced;
	అక్షరం *సందేశం;
	u_char *p;
	పూర్ణాంకం r;

	ఒకవేళ ((logmsg = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new");

	/* Read length */
	ఒకవేళ ((r = sshbuf_reserve(logmsg, 4, &p)) != 0)
		fatal_fr(r, "reserve len");
	ఒకవేళ (atomicio(పఠ, pmonitor->m_log_recvfd, p, 4) != 4) {
		ఒకవేళ (errno == EPIPE) {
			sshbuf_free(logmsg);
			debug_f("child log fd closed");
			close(pmonitor->m_log_recvfd);
			pmonitor->m_log_recvfd = -1;
			తిరిగి -1;
		}
		fatal_f("log fd read: %s", strerror(errno));
	}
	ఒకవేళ ((r = sshbuf_get_u32(logmsg, &len)) != 0)
		fatal_fr(r, "parse len");
	ఒకవేళ (len <= 4 || len > 8192)
		fatal_f("invalid log message length %u", len);

	/* Read severity, message */
	sshbuf_reset(logmsg);
	ఒకవేళ ((r = sshbuf_reserve(logmsg, len, &p)) != 0)
		fatal_fr(r, "reserve msg");
	ఒకవేళ (atomicio(పఠ, pmonitor->m_log_recvfd, p, len) != len)
		fatal_f("log fd read: %s", strerror(errno));
	ఒకవేళ ((r = sshbuf_get_u32(logmsg, &level)) != 0 ||
	    (r = sshbuf_get_u32(logmsg, &forced)) != 0 ||
	    (r = sshbuf_get_cstring(logmsg, &సందేశం, ఖాళీ)) != 0)
		fatal_fr(r, "parse");

	/* Log it */
	ఒకవేళ (log_level_name(level) == ఖాళీ)
		fatal_f("invalid log level %u (corrupted message?)", level);
	sshlogdirect(level, forced, "%s [%s]", సందేశం,
	    mon_dispatch == mon_dispatch_postauth20 ? "postauth" : "preauth");

	sshbuf_free(logmsg);
	విడుదల(సందేశం);

	తిరిగి 0;
}

స్థిర పూర్ణాంకం
monitor_read(నిర్మాణం ssh *ssh, నిర్మాణం monitor *pmonitor, నిర్మాణం mon_పట్టిక *ent,
    నిర్మాణం mon_పట్టిక **pent)
{
	నిర్మాణం sshbuf *m;
	పూర్ణాంకం r, ret;
	u_char type;
	నిర్మాణం pollfd pfd[2];

	కొరకు (;;) {
		memset(&pfd, 0, పరిమాణం(pfd));
		pfd[0].fd = pmonitor->m_sendfd;
		pfd[0].events = POLLIN;
		pfd[1].fd = pmonitor->m_log_recvfd;
		pfd[1].events = pfd[1].fd == -1 ? 0 : POLLIN;
		ఒకవేళ (poll(pfd, pfd[1].fd == -1 ? 1 : 2, -1) == -1) {
			ఒకవేళ (errno == EINTR || errno == EAGAIN)
				కొనసాగు;
			fatal_f("poll: %s", strerror(errno));
		}
		ఒకవేళ (pfd[1].revents) {
			/*
			 * Drain all log messages before processing next
			 * monitor request.
			 */
			monitor_read_log(pmonitor);
			కొనసాగు;
		}
		ఒకవేళ (pfd[0].revents)
			ఆపు;  /* Continues below */
	}

	ఒకవేళ ((m = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new");

	mm_request_receive(pmonitor->m_sendfd, m);
	ఒకవేళ ((r = sshbuf_get_u8(m, &type)) != 0)
		fatal_fr(r, "parse type");

	debug3_f("checking request %d", type);

	అయితే (ent->f != ఖాళీ) {
		ఒకవేళ (ent->type == type)
			ఆపు;
		ent++;
	}

	ఒకవేళ (ent->f != ఖాళీ) {
		ఒకవేళ (!(ent->flags & MON_PERMIT))
			fatal_f("unpermitted request %d", type);
		ret = (*ent->f)(ssh, pmonitor->m_sendfd, m);
		sshbuf_free(m);

		/* The child may use this request only once, disable it */
		ఒకవేళ (ent->flags & MON_ONCE) {
			debug2_f("%d used once, disabling now", type);
			ent->flags &= ~MON_PERMIT;
		}

		ఒకవేళ (pent != ఖాళీ)
			*pent = ent;

		తిరిగి ret;
	}

	fatal_f("unsupported request: %d", type);

	/* NOTREACHED */
	తిరిగి (-1);
}

/* allowed key state */
స్థిర పూర్ణాంకం
monitor_allowed_కీలకం(స్థిరరాశి u_char *blob, u_int bloblen)
{
	/* make sure key is allowed */
	ఒకవేళ (కీలకం_blob == ఖాళీ || కీలకం_bloblen != bloblen ||
	    timingsafe_bcmp(కీలకం_blob, blob, కీలకం_bloblen))
		తిరిగి (0);
	తిరిగి (1);
}

స్థిర శూన్య
monitor_reset_కీలకం_state(శూన్య)
{
	/* reset state */
	విడుదల(కీలకం_blob);
	విడుదల(hostbased_cuser);
	విడుదల(hostbased_chost);
	sshauthopt_free(కీలకం_opts);
	కీలకం_blob = ఖాళీ;
	కీలకం_bloblen = 0;
	కీలకం_blobtype = MM_NOKEY;
	కీలకం_opts = ఖాళీ;
	hostbased_cuser = ఖాళీ;
	hostbased_chost = ఖాళీ;
}

పూర్ణాంకం
mm_answer_state(నిర్మాణం ssh *ssh, పూర్ణాంకం sock, నిర్మాణం sshbuf *వాడని)
{
	నిర్మాణం sshbuf *m = ఖాళీ, *config = ఖాళీ, *hostkeys = ఖాళీ;
	నిర్మాణం sshbuf *opts = ఖాళీ, *confdata = ఖాళీ;
	పూర్ణాంకం postauth;
	పూర్ణాంకం r;

	debug_f("config len %zu", sshbuf_len(cfg));

	ఒకవేళ ((m = sshbuf_new()) == ఖాళీ ||
	    (config = sshbuf_new()) == ఖాళీ ||
	    (opts = sshbuf_new()) == ఖాళీ ||
	    (confdata = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");

	hostkeys = pack_hostkeys();
	ఒకవేళ ((r = serialise_server_options(&options, &config)) != 0)
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
	ఒకవేళ ((r = sshbuf_put_stringb(m, config)) != 0 ||
	    (r = sshbuf_put_u64(m, options.timing_secret)) != 0 ||
	    (r = sshbuf_put_stringb(m, hostkeys)) != 0 ||
	    (r = sshbuf_put_stringb(m, ssh->kex->server_సంస్కరణ)) != 0 ||
	    (r = sshbuf_put_stringb(m, ssh->kex->client_సంస్కరణ)) != 0)
		fatal_fr(r, "compose config");

	postauth = (authctxt && authctxt->pw && authctxt->authenticated);
	ఒకవేళ (postauth) {
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

	తిరిగి (0);
}

#నిర్వచితమైతే WITH_OPENSSL
పూర్ణాంకం
mm_answer_moduli(నిర్మాణం ssh *ssh, పూర్ణాంకం sock, నిర్మాణం sshbuf *m)
{
	DH *dh;
	స్థిరరాశి BIGNUM *dh_p, *dh_g;
	పూర్ణాంకం r;
	u_int min, want, max;

	ఒకవేళ ((r = sshbuf_get_u32(m, &min)) != 0 ||
	    (r = sshbuf_get_u32(m, &want)) != 0 ||
	    (r = sshbuf_get_u32(m, &max)) != 0)
		fatal_fr(r, "parse");

	debug3_f("got parameters: %d %d %d", min, want, max);
	/* We need to check here, too, in case the child got corrupted */
	ఒకవేళ (max < min || want < min || max < want)
		fatal_f("bad parameters: %d %d %d", min, want, max);

	sshbuf_reset(m);

	dh = ఎంచుకో_dh(min, want, max);
	ఒకవేళ (dh == ఖాళీ) {
		ఒకవేళ ((r = sshbuf_put_u8(m, 0)) != 0)
			fatal_fr(r, "assemble empty");
	} లేకపోతే {
		/* Send first bignum */
		DH_get0_pqg(dh, &dh_p, ఖాళీ, &dh_g);
		ఒకవేళ ((r = sshbuf_put_u8(m, 1)) != 0 ||
		    (r = sshbuf_put_bignum2(m, dh_p)) != 0 ||
		    (r = sshbuf_put_bignum2(m, dh_g)) != 0)
			fatal_fr(r, "assemble");

		DH_free(dh);
	}
	mm_request_send(sock, MONITOR_ANS_MODULI, m);
	తిరిగి (0);
}
#అయితే_ముగింపు

పూర్ణాంకం
mm_answer_setcompat(నిర్మాణం ssh *ssh, పూర్ణాంకం sock, నిర్మాణం sshbuf *m)
{
	పూర్ణాంకం r;

	debug3_f("entering");

	ఒకవేళ ((r = sshbuf_get_u32(m, &ssh->compat)) != 0)
		fatal_fr(r, "parse");
	compat_సమితి = 1;

	తిరిగి (0);
}

పూర్ణాంకం
mm_answer_sign(నిర్మాణం ssh *ssh, పూర్ణాంకం sock, నిర్మాణం sshbuf *m)
{
	బాహ్య పూర్ణాంకం auth_sock;			/* XXX move to state struct? */
	నిర్మాణం sshkey *pubkey, *కీలకం;
	నిర్మాణం sshbuf *sigbuf = ఖాళీ;
	u_char *p = ఖాళీ, *signature = ఖాళీ;
	అక్షరం *alg = ఖాళీ;
	కొలత_t datlen, siglen;
	పూర్ణాంకం r, is_proof = 0, keyid;
	u_int compat;
	స్థిరరాశి అక్షరం proof_req[] = "hostkeys-prove-00@openssh.com";
	స్థిర పూర్ణాంకం nhostkey_proofs_పూర్తి, *hostkey_proofs_పూర్తి;

	debug3_f("entering");

	/* Make sure the unpriv process sent the compat bits already */
	ఒకవేళ (!compat_సమితి)
		fatal_f("state error: setcompat never called");

	ఒకవేళ ((r = sshkey_froms(m, &pubkey)) != 0 ||
	    (r = sshbuf_get_string(m, &p, &datlen)) != 0 ||
	    (r = sshbuf_get_cstring(m, &alg, ఖాళీ)) != 0 ||
	    (r = sshbuf_get_u32(m, &compat)) != 0)
		fatal_fr(r, "parse");

	ఒకవేళ ((keyid = get_hostkey_సూచీ(pubkey, 1, ssh)) == -1)
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
	ఒకవేళ (datlen != 20 && datlen != 32 && datlen != 48 && datlen != 64) {
		/*
		 * Construct expected hostkey proof and compare it to what
		 * the client sent us.
		 */
		ఒకవేళ (session_id2_len == 0) /* hostkeys is never first */
			fatal_f("bad data length: %zu", datlen);
		ఒకవేళ ((కీలకం = get_hostkey_ప్రజా_by_సూచీ(keyid, ssh)) == ఖాళీ)
			fatal_f("no hostkey for index %d", keyid);
		ఒకవేళ (keyid >= nhostkey_proofs_పూర్తి) {
			hostkey_proofs_పూర్తి = xrecallocarray(
			    hostkey_proofs_పూర్తి, nhostkey_proofs_పూర్తి,
			    keyid + 1, పరిమాణం(*hostkey_proofs_పూర్తి));
			nhostkey_proofs_పూర్తి = keyid + 1;
		}
		ఒకవేళ (hostkey_proofs_పూర్తి[keyid]) {
			fatal_f("hostkeys proof requested for %s key %d "
			    "multiple times", sshkey_type(కీలకం), keyid);
		}
		hostkey_proofs_పూర్తి[keyid] = 1;
		ఒకవేళ ((sigbuf = sshbuf_new()) == ఖాళీ)
			fatal_f("sshbuf_new");
		ఒకవేళ ((r = sshbuf_put_cstring(sigbuf, proof_req)) != 0 ||
		    (r = sshbuf_put_string(sigbuf, session_id2,
		    session_id2_len)) != 0 ||
		    (r = sshkey_puts(కీలకం, sigbuf)) != 0)
			fatal_fr(r, "assemble private key proof");
		ఒకవేళ (datlen != sshbuf_len(sigbuf) ||
		    memcmp(p, sshbuf_ptr(sigbuf), sshbuf_len(sigbuf)) != 0)
			fatal_f("bad data length: %zu, hostkey proof len %zu",
			    datlen, sshbuf_len(sigbuf));
		sshbuf_free(sigbuf);
		is_proof = 1;
	}

	/* save session id, it will be passed on the first call */
	ఒకవేళ (session_id2_len == 0) {
		session_id2_len = datlen;
		session_id2 = xmalloc(session_id2_len);
		జ్ఞాపకం_నకలు(session_id2, p, session_id2_len);
	}

	ఒకవేళ ((కీలకం = get_hostkey_by_సూచీ(keyid)) != ఖాళీ) {
		ఒకవేళ ((r = sshkey_sign(కీలకం, &signature, &siglen, p, datlen, alg,
		    options.sk_provider, ఖాళీ, compat)) != 0)
			fatal_fr(r, "sign");
	} లేకపోతే ఒకవేళ ((కీలకం = get_hostkey_ప్రజా_by_సూచీ(keyid, ssh)) != ఖాళీ &&
	    auth_sock > 0) {
		ఒకవేళ ((r = ssh_agent_sign(auth_sock, కీలకం, &signature, &siglen,
		    p, datlen, alg, compat)) != 0)
			fatal_fr(r, "agent sign");
	} లేకపోతే
		fatal_f("no hostkey from index %d", keyid);

	debug3_f("%s %s signature len=%zu", alg,
	    is_proof ? "hostkey proof" : "KEX", siglen);

	sshbuf_reset(m);
	ఒకవేళ ((r = sshbuf_put_string(m, signature, siglen)) != 0)
		fatal_fr(r, "assemble");

	విడుదల(alg);
	విడుదల(p);
	విడుదల(signature);

	mm_request_send(sock, MONITOR_ANS_SIGN, m);

	/* Turn on permissions for getpwnam */
	monitor_permit(mon_dispatch, MONITOR_REQ_PWNAM, 1);

	తిరిగి (0);
}

#నిర్వచించు PUTPW(b, id) \
	చేయి { \
		ఒకవేళ ((r = sshbuf_put_string(b, \
		    &pwent->id, పరిమాణం(pwent->id))) != 0) \
			fatal_fr(r, "assemble %s", #id); \
	} అయితే (0)

శూన్య
mm_encode_server_options(నిర్మాణం sshbuf *m)
{
	పూర్ణాంకం r;
	నిర్మాణం sshbuf *config;

	ఒకవేళ ((config = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");
	ఒకవేళ ((r = serialise_server_options(&options, &config)) != 0)
		fatal_fr(r, "serialise_server_options");
	ఒకవేళ ((r = sshbuf_put_stringb(m, config)) != 0)
		fatal_fr(r, "assemble options");
	sshbuf_free(config);
}

/* Retrieves the password entry and also checks if the user is permitted */
పూర్ణాంకం
mm_answer_pwnamallow(నిర్మాణం ssh *ssh, పూర్ణాంకం sock, నిర్మాణం sshbuf *m)
{
	నిర్మాణం passwd *pwent;
	పూర్ణాంకం r, allowed = 0;

	debug3_f("entering");

	/* Make sure the unpriv process sent the compat bits already */
	ఒకవేళ (!compat_సమితి)
		fatal_f("state error: setcompat never called");

	ఒకవేళ (authctxt->attempt++ != 0)
		fatal_f("multiple attempts for getpwnam");

	ఒకవేళ ((r = sshbuf_get_cstring(m, &authctxt->user, ఖాళీ)) != 0)
		fatal_fr(r, "parse");

	pwent = getpwnamallow(ssh, authctxt->user);

	setproctitle("%s [priv]", pwent ? authctxt->user : "unknown");

	sshbuf_reset(m);

	ఒకవేళ (pwent == ఖాళీ) {
		invalid_user = 1;
		ఒకవేళ ((r = sshbuf_put_u8(m, 0)) != 0)
			fatal_fr(r, "assemble fakepw");
		authctxt->pw = fakepw();
		వెళ్ళు బహిర్గతం;
	}

	allowed = 1;
	authctxt->pw = pwent;
	authctxt->valid = 1;

	/* XXX send fake class/dir/shell, etc. */
	ఒకవేళ ((r = sshbuf_put_u8(m, 1)) != 0)
		fatal_fr(r, "assemble ok");
	PUTPW(m, pw_uid);
	PUTPW(m, pw_gid);
#నిర్వచితమైతే HAVE_STRUCT_PASSWD_PW_CHANGE
	PUTPW(m, pw_change);
#అయితే_ముగింపు
#నిర్వచితమైతే HAVE_STRUCT_PASSWD_PW_EXPIRE
	PUTPW(m, pw_expire);
#అయితే_ముగింపు
	ఒకవేళ ((r = sshbuf_put_cstring(m, pwent->pw_name)) != 0 ||
	    (r = sshbuf_put_cstring(m, "*")) != 0 ||
#నిర్వచితమైతే HAVE_STRUCT_PASSWD_PW_GECOS
	    (r = sshbuf_put_cstring(m, pwent->pw_gecos)) != 0 ||
#అయితే_ముగింపు
#నిర్వచితమైతే HAVE_STRUCT_PASSWD_PW_CLASS
	    (r = sshbuf_put_cstring(m, pwent->pw_class)) != 0 ||
#అయితే_ముగింపు
	    (r = sshbuf_put_cstring(m, pwent->pw_dir)) != 0 ||
	    (r = sshbuf_put_cstring(m, pwent->pw_shell)) != 0)
		fatal_fr(r, "assemble pw");

 బహిర్గతం:
	ssh_packet_సమితి_log_preamble(ssh, "%suser %s",
	    authctxt->valid ? "authenticating" : "invalid ", authctxt->user);

	ఒకవేళ (options.refuse_connection) {
		logit("administratively prohibited connection for "
		    "%s%s from %.128s port %d",
		    authctxt->valid ? "" : "invalid user ",
		    authctxt->user, ssh_remote_ipaddr(ssh),
		    ssh_remote_పోర్టు(ssh));
		cleanup_exit(EXIT_CONFIG_REFUSED);
	}

	/* Send active options to unpriv */
	mm_encode_server_options(m);

	/* Create valid auth method lists */
	ఒకవేళ (auth2_అమరిక_methods_lists(authctxt) != 0) {
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

#నిర్వచితమైతే USE_PAM
	ఒకవేళ (options.use_pam)
		monitor_permit(mon_dispatch, MONITOR_REQ_PAM_ప్రారంభం, 1);
#అయితే_ముగింపు

	తిరిగి (0);
}

పూర్ణాంకం mm_answer_auth2_read_banner(నిర్మాణం ssh *ssh, పూర్ణాంకం sock, నిర్మాణం sshbuf *m)
{
	అక్షరం *banner;
	పూర్ణాంకం r;

	sshbuf_reset(m);
	banner = auth2_read_banner();
	ఒకవేళ ((r = sshbuf_put_cstring(m, banner != ఖాళీ ? banner : "")) != 0)
		fatal_fr(r, "assemble");
	mm_request_send(sock, MONITOR_ANS_AUTH2_READ_BANNER, m);
	విడుదల(banner);

	తిరిగి (0);
}

పూర్ణాంకం
mm_answer_authserv(నిర్మాణం ssh *ssh, పూర్ణాంకం sock, నిర్మాణం sshbuf *m)
{
	పూర్ణాంకం r;

	monitor_permit_authentications(1);

	ఒకవేళ ((r = sshbuf_get_cstring(m, &authctxt->service, ఖాళీ)) != 0 ||
	    (r = sshbuf_get_cstring(m, &authctxt->style, ఖాళీ)) != 0)
		fatal_fr(r, "parse");
	debug3_f("service=%s, style=%s", authctxt->service, authctxt->style);

	ఒకవేళ (అక్షరశ్రేణి_పొడవు(authctxt->style) == 0) {
		విడుదల(authctxt->style);
		authctxt->style = ఖాళీ;
	}

	తిరిగి (0);
}

/*
 * Check that the key type appears in the supplied pattern list, ignoring
 * mismatches in the signature algorithm. (Signature algorithm checks are
 * performed in the unprivileged authentication code).
 * Returns 1 on success, 0 otherwise.
 */
స్థిర పూర్ణాంకం
కీలకం_పునాది_type_సరిపోలిక(స్థిరరాశి అక్షరం *పద్ధతి, స్థిరరాశి నిర్మాణం sshkey *కీలకం,
    స్థిరరాశి అక్షరం *list)
{
	అక్షరం *s, *l, *ol = xstrdup(list);
	పూర్ణాంకం దొరికింది = 0;

	l = ol;
	కొరకు ((s = strsep(&l, ",")); s && *s != '\0'; (s = strsep(&l, ","))) {
		ఒకవేళ (sshkey_type_from_name(s) == కీలకం->type) {
			దొరికింది = 1;
			ఆపు;
		}
	}
	ఒకవేళ (!దొరికింది) {
		error("%s key type %s is not in permitted list %s", పద్ధతి,
		    sshkey_ssh_name(కీలకం), list);
	}

	విడుదల(ol);
	తిరిగి దొరికింది;
}

పూర్ణాంకం
mm_answer_authpassword(నిర్మాణం ssh *ssh, పూర్ణాంకం sock, నిర్మాణం sshbuf *m)
{
	స్థిర పూర్ణాంకం call_లెక్క;
	అక్షరం *passwd;
	పూర్ణాంకం r, authenticated;
	కొలత_t plen;

	ఒకవేళ (!options.password_authentication)
		fatal_f("password authentication not enabled");
	ఒకవేళ ((r = sshbuf_get_cstring(m, &passwd, &plen)) != 0)
		fatal_fr(r, "parse");
	/* Only authenticate if the context is valid */
	authenticated = options.password_authentication &&
	    auth_password(ssh, passwd);
	freezero(passwd, plen);

	sshbuf_reset(m);
	ఒకవేళ ((r = sshbuf_put_u32(m, authenticated)) != 0)
		fatal_fr(r, "assemble");
#నిర్వచితమైతే USE_PAM
	ఒకవేళ ((r = sshbuf_put_u32(m, sshpam_get_maxtries_reached())) != 0)
		fatal_fr(r, "assemble PAM");
#అయితే_ముగింపు

	debug3_f("sending result %d", authenticated);
	mm_request_send(sock, MONITOR_ANS_AUTHPASSWORD, m);

	call_లెక్క++;
	ఒకవేళ (plen == 0 && call_లెక్క == 1)
		auth_పద్ధతి = "none";
	లేకపోతే
		auth_పద్ధతి = "password";

	/* Causes monitor loop to terminate if authenticated */
	తిరిగి (authenticated);
}

#నిర్వచితమైతే BSD_AUTH
పూర్ణాంకం
mm_answer_bsdauthquery(నిర్మాణం ssh *ssh, పూర్ణాంకం sock, నిర్మాణం sshbuf *m)
{
	అక్షరం *name, *infotxt;
	u_int numprompts, *echo_on, success;
	అక్షరం **prompts;
	పూర్ణాంకం r;

	ఒకవేళ (!options.kbd_interactive_authentication)
		fatal_f("kbd-int authentication not enabled");
	success = bsdauth_query(authctxt, &name, &infotxt, &numprompts,
	    &prompts, &echo_on) < 0 ? 0 : 1;

	sshbuf_reset(m);
	ఒకవేళ ((r = sshbuf_put_u32(m, success)) != 0)
		fatal_fr(r, "assemble");
	ఒకవేళ (success) {
		ఒకవేళ ((r = sshbuf_put_cstring(m, prompts[0])) != 0)
			fatal_fr(r, "assemble prompt");
	}

	debug3_f("sending challenge success: %u", success);
	mm_request_send(sock, MONITOR_ANS_BSDAUTHQUERY, m);

	ఒకవేళ (success) {
		విడుదల(name);
		విడుదల(infotxt);
		విడుదల(prompts);
		విడుదల(echo_on);
	}

	తిరిగి (0);
}

పూర్ణాంకం
mm_answer_bsdauthrespond(నిర్మాణం ssh *ssh, పూర్ణాంకం sock, నిర్మాణం sshbuf *m)
{
	అక్షరం *response;
	పూర్ణాంకం r, authok;

	ఒకవేళ (!options.kbd_interactive_authentication)
		fatal_f("kbd-int authentication not enabled");
	ఒకవేళ (authctxt->as == ఖాళీ)
		fatal_f("no bsd auth session");

	ఒకవేళ ((r = sshbuf_get_cstring(m, &response, ఖాళీ)) != 0)
		fatal_fr(r, "parse");
	authok = options.kbd_interactive_authentication &&
	    auth_userresponse(authctxt->as, response, 0);
	authctxt->as = ఖాళీ;
	debug3_f("<%s> = <%d>", response, authok);
	విడుదల(response);

	sshbuf_reset(m);
	ఒకవేళ ((r = sshbuf_put_u32(m, authok)) != 0)
		fatal_fr(r, "assemble");

	debug3_f("sending authenticated: %d", authok);
	mm_request_send(sock, MONITOR_ANS_BSDAUTHRESPOND, m);

	auth_పద్ధతి = "keyboard-interactive";
	auth_submethod = "bsdauth";

	తిరిగి (authok != 0);
}
#అయితే_ముగింపు

#నిర్వచితమైతే USE_PAM
పూర్ణాంకం
mm_answer_pam_ప్రారంభం(నిర్మాణం ssh *ssh, పూర్ణాంకం sock, నిర్మాణం sshbuf *m)
{
	ఒకవేళ (!options.use_pam)
		fatal_f("UsePAM not set, but ended up in %s anyway", __func__);

	ప్రారంభం_pam(ssh);

	monitor_permit(mon_dispatch, MONITOR_REQ_PAM_ACCOUNT, 1);
	ఒకవేళ (options.kbd_interactive_authentication)
		monitor_permit(mon_dispatch, MONITOR_REQ_PAM_INIT_CTX, 1);

	తిరిగి (0);
}

పూర్ణాంకం
mm_answer_pam_account(నిర్మాణం ssh *ssh, పూర్ణాంకం sock, నిర్మాణం sshbuf *m)
{
	u_int ret;
	పూర్ణాంకం r;

	ఒకవేళ (!options.use_pam)
		fatal_f("PAM not enabled");

	ret = do_pam_account();

	ఒకవేళ ((r = sshbuf_put_u32(m, ret)) != 0 ||
	    (r = sshbuf_put_stringb(m, loginmsg)) != 0)
		fatal_fr(r, "buffer error");
	sshbuf_reset(loginmsg);

	mm_request_send(sock, MONITOR_ANS_PAM_ACCOUNT, m);

	తిరిగి (ret);
}

స్థిర శూన్య *sshpam_ctxt, *sshpam_authok;
బాహ్య KbdintDevice sshpam_device;

పూర్ణాంకం
mm_answer_pam_init_ctx(నిర్మాణం ssh *ssh, పూర్ణాంకం sock, నిర్మాణం sshbuf *m)
{
	u_int ok = 0;
	పూర్ణాంకం r;

	debug3_f("entering");
	ఒకవేళ (!options.kbd_interactive_authentication)
		fatal_f("kbd-int authentication not enabled");
	ఒకవేళ (sshpam_ctxt != ఖాళీ)
		fatal_f("already called");
	sshpam_ctxt = (sshpam_device.init_ctx)(authctxt);
	sshpam_authok = ఖాళీ;
	sshbuf_reset(m);
	ఒకవేళ (sshpam_ctxt != ఖాళీ) {
		monitor_permit(mon_dispatch, MONITOR_REQ_PAM_FREE_CTX, 1);
		monitor_permit(mon_dispatch, MONITOR_REQ_PAM_QUERY, 1);
		ok = 1;
	}
	ఒకవేళ ((r = sshbuf_put_u32(m, ok)) != 0)
		fatal_fr(r, "buffer error");
	mm_request_send(sock, MONITOR_ANS_PAM_INIT_CTX, m);
	తిరిగి (0);
}

పూర్ణాంకం
mm_answer_pam_query(నిర్మాణం ssh *ssh, పూర్ణాంకం sock, నిర్మాణం sshbuf *m)
{
	అక్షరం *name = ఖాళీ, *info = ఖాళీ, **prompts = ఖాళీ;
	u_int i, అంకె = 0, *echo_on = 0;
	పూర్ణాంకం r, ret;

	debug3_f("entering");
	sshpam_authok = ఖాళీ;
	ఒకవేళ (sshpam_ctxt == ఖాళీ)
		fatal_f("no context");
	ret = (sshpam_device.query)(sshpam_ctxt, &name, &info,
	    &అంకె, &prompts, &echo_on);
	ఒకవేళ (ret == 0 && అంకె == 0 && sshpam_priv_kbdint_authdone(sshpam_ctxt))
		sshpam_authok = sshpam_ctxt;
	ఒకవేళ (అంకె > 1 || name == ఖాళీ || info == ఖాళీ)
		fatal("sshpam_device.query failed");
	monitor_permit(mon_dispatch, MONITOR_REQ_PAM_RESPOND, 1);
	sshbuf_reset(m);
	ఒకవేళ ((r = sshbuf_put_u32(m, ret)) != 0 ||
	    (r = sshbuf_put_cstring(m, name)) != 0 ||
	    (r = sshbuf_put_cstring(m, info)) != 0 ||
	    (r = sshbuf_put_u32(m, sshpam_get_maxtries_reached())) != 0 ||
	    (r = sshbuf_put_u32(m, అంకె)) != 0)
		fatal_fr(r, "buffer error");
	విడుదల(name);
	విడుదల(info);
	కొరకు (i = 0; i < అంకె; ++i) {
		ఒకవేళ ((r = sshbuf_put_cstring(m, prompts[i])) != 0 ||
		    (r = sshbuf_put_u32(m, echo_on[i])) != 0)
			fatal_fr(r, "buffer error");
		విడుదల(prompts[i]);
	}
	విడుదల(prompts);
	విడుదల(echo_on);
	auth_పద్ధతి = "keyboard-interactive";
	auth_submethod = "pam";
	mm_request_send(sock, MONITOR_ANS_PAM_QUERY, m);
	తిరిగి (0);
}

పూర్ణాంకం
mm_answer_pam_respond(నిర్మాణం ssh *ssh, పూర్ణాంకం sock, నిర్మాణం sshbuf *m)
{
	అక్షరం **resp;
	u_int i, అంకె;
	పూర్ణాంకం r, ret;

	debug3_f("entering");
	ఒకవేళ (sshpam_ctxt == ఖాళీ)
		fatal_f("no context");
	sshpam_authok = ఖాళీ;
	ఒకవేళ ((r = sshbuf_get_u32(m, &అంకె)) != 0)
		fatal_fr(r, "buffer error");
	ఒకవేళ (అంకె > PAM_MAX_అంకె_సందేశం) {
		fatal_f("Too many PAM messages, got %u, expected <= %u",
		    అంకె, (గుర్తులేని)PAM_MAX_అంకె_సందేశం);
	}
	ఒకవేళ (అంకె > 0) {
		resp = xcalloc(అంకె, పరిమాణం(అక్షరం *));
		కొరకు (i = 0; i < అంకె; ++i) {
			ఒకవేళ ((r = sshbuf_get_cstring(m, &(resp[i]), ఖాళీ)) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
		}
		ret = (sshpam_device.respond)(sshpam_ctxt, అంకె, resp);
		కొరకు (i = 0; i < అంకె; ++i)
			విడుదల(resp[i]);
		విడుదల(resp);
	} లేకపోతే {
		ret = (sshpam_device.respond)(sshpam_ctxt, అంకె, ఖాళీ);
	}
	sshbuf_reset(m);
	ఒకవేళ ((r = sshbuf_put_u32(m, ret)) != 0)
		fatal_fr(r, "buffer error");
	mm_request_send(sock, MONITOR_ANS_PAM_RESPOND, m);
	auth_పద్ధతి = "keyboard-interactive";
	auth_submethod = "pam";
	ఒకవేళ (ret == 0)
		sshpam_authok = sshpam_ctxt;
	తిరిగి (0);
}

పూర్ణాంకం
mm_answer_pam_free_ctx(నిర్మాణం ssh *ssh, పూర్ణాంకం sock, నిర్మాణం sshbuf *m)
{
	పూర్ణాంకం r = sshpam_authok != ఖాళీ && sshpam_authok == sshpam_ctxt;

	debug3_f("entering");
	ఒకవేళ (sshpam_ctxt == ఖాళీ)
		fatal_f("no context");
	(sshpam_device.free_ctx)(sshpam_ctxt);
	sshpam_ctxt = sshpam_authok = ఖాళీ;
	sshbuf_reset(m);
	mm_request_send(sock, MONITOR_ANS_PAM_FREE_CTX, m);
	/* Allow another attempt */
	monitor_permit(mon_dispatch, MONITOR_REQ_PAM_INIT_CTX, 1);
	auth_పద్ధతి = "keyboard-interactive";
	auth_submethod = "pam";
	తిరిగి r;
}
#అయితే_ముగింపు

పూర్ణాంకం
mm_answer_keyallowed(నిర్మాణం ssh *ssh, పూర్ణాంకం sock, నిర్మాణం sshbuf *m)
{
	నిర్మాణం sshkey *కీలకం = ఖాళీ;
	అక్షరం *cuser, *chost;
	u_int pubkey_auth_attempt;
	u_int type = 0;
	పూర్ణాంకం r, allowed = 0;
	నిర్మాణం sshauthopt *opts = ఖాళీ;

	debug3_f("entering");
	ఒకవేళ ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_cstring(m, &cuser, ఖాళీ)) != 0 ||
	    (r = sshbuf_get_cstring(m, &chost, ఖాళీ)) != 0 ||
	    (r = sshkey_froms(m, &కీలకం)) != 0 ||
	    (r = sshbuf_get_u32(m, &pubkey_auth_attempt)) != 0)
		fatal_fr(r, "parse");

	ఒకవేళ (కీలకం != ఖాళీ && authctxt->valid) {
		ఎంపిక (type) {
		స్థితి MM_USERKEY:
			auth_పద్ధతి = "publickey";
			ఒకవేళ (!options.pubkey_authentication)
				ఆపు;
			ఒకవేళ (auth2_కీలకం_already_వాడిన(authctxt, కీలకం))
				ఆపు;
			ఒకవేళ (!కీలకం_పునాది_type_సరిపోలిక(auth_పద్ధతి, కీలకం,
			    options.pubkey_accepted_algos))
				ఆపు;
			allowed = user_కీలకం_allowed(ssh, authctxt->pw, కీలకం,
			    pubkey_auth_attempt, &opts);
			ఆపు;
		స్థితి MM_HOSTKEY:
			auth_పద్ధతి = "hostbased";
			ఒకవేళ (!options.hostbased_authentication)
				ఆపు;
			ఒకవేళ (auth2_కీలకం_already_వాడిన(authctxt, కీలకం))
				ఆపు;
			ఒకవేళ (!కీలకం_పునాది_type_సరిపోలిక(auth_పద్ధతి, కీలకం,
			    options.hostbased_accepted_algos))
				ఆపు;
			allowed = hostbased_కీలకం_allowed(ssh, authctxt->pw,
			    cuser, chost, కీలకం);
			auth2_రికార్డు_info(authctxt,
			    "client user \"%.100s\", client host \"%.100s\"",
			    cuser, chost);
			ఆపు;
		అప్రమేయ:
			fatal_f("unknown key type %u", type);
			ఆపు;
		}
	}

	debug3_f("%s authentication%s: %s key is %s", auth_పద్ధతి,
	    pubkey_auth_attempt ? "" : " test",
	    (కీలకం == ఖాళీ || !authctxt->valid) ? "invalid" : sshkey_type(కీలకం),
	    allowed ? "allowed" : "not allowed");

	auth2_రికార్డు_కీలకం(authctxt, 0, కీలకం);

	/* clear temporarily storage (used by verify) */
	monitor_reset_కీలకం_state();

	ఒకవేళ (allowed) {
		/* Save temporarily for comparison in verify */
		ఒకవేళ ((r = sshkey_గమ్యం_blob(కీలకం, &కీలకం_blob, &కీలకం_bloblen)) != 0)
			fatal_fr(r, "sshkey_to_blob");
		కీలకం_blobtype = type;
		కీలకం_opts = opts;
		hostbased_cuser = cuser;
		hostbased_chost = chost;
	} లేకపోతే {
		/* Log failed attempt */
		auth_log(ssh, 0, 0, auth_పద్ధతి, ఖాళీ);
		విడుదల(cuser);
		విడుదల(chost);
	}
	sshkey_free(కీలకం);

	sshbuf_reset(m);
	ఒకవేళ ((r = sshbuf_put_u32(m, allowed)) != 0)
		fatal_fr(r, "assemble");
	ఒకవేళ (opts != ఖాళీ && (r = sshauthopt_serialise(opts, m, 1)) != 0)
		fatal_fr(r, "sshauthopt_serialise");
	mm_request_send(sock, MONITOR_ANS_KEYALLOWED, m);

	ఒకవేళ (!allowed)
		sshauthopt_free(opts);

	తిరిగి (0);
}

స్థిర పూర్ణాంకం
monitor_valid_userblob(నిర్మాణం ssh *ssh, స్థిరరాశి u_char *దత్తాంశం, u_int datalen)
{
	నిర్మాణం sshbuf *b;
	నిర్మాణం sshkey *hostkey = ఖాళీ;
	స్థిరరాశి u_char *p;
	అక్షరం *userstyle, *cp;
	కొలత_t len;
	u_char type;
	పూర్ణాంకం hostbound = 0, r, fail = 0;

	ఒకవేళ ((b = sshbuf_from(దత్తాంశం, datalen)) == ఖాళీ)
		fatal_f("sshbuf_from");

	ఒకవేళ ((r = sshbuf_get_string_ప్రత్యక్ష(b, &p, &len)) != 0)
		fatal_fr(r, "parse sessionid");
	ఒకవేళ ((session_id2 == ఖాళీ) ||
	    (len != session_id2_len) ||
	    (timingsafe_bcmp(p, session_id2, session_id2_len) != 0))
		fail++;
	ఒకవేళ ((r = sshbuf_get_u8(b, &type)) != 0)
		fatal_fr(r, "parse type");
	ఒకవేళ (type != SSH2_సందేశం_USERAUTH_REQUEST)
		fail++;
	ఒకవేళ ((r = sshbuf_get_cstring(b, &cp, ఖాళీ)) != 0)
		fatal_fr(r, "parse userstyle");
	xasprintf(&userstyle, "%s%s%s", authctxt->user,
	    authctxt->style ? ":" : "",
	    authctxt->style ? authctxt->style : "");
	ఒకవేళ (strcmp(userstyle, cp) != 0) {
		logit("wrong user name passed to monitor: "
		    "expected %s != %.100s", userstyle, cp);
		fail++;
	}
	విడుదల(userstyle);
	విడుదల(cp);
	ఒకవేళ ((r = sshbuf_skip_string(b)) != 0 ||	/* service */
	    (r = sshbuf_get_cstring(b, &cp, ఖాళీ)) != 0)
		fatal_fr(r, "parse method");
	ఒకవేళ (strcmp("publickey", cp) != 0) {
		ఒకవేళ (strcmp("publickey-hostbound-v00@openssh.com", cp) == 0)
			hostbound = 1;
		లేకపోతే
			fail++;
	}
	విడుదల(cp);
	ఒకవేళ ((r = sshbuf_get_u8(b, &type)) != 0)
		fatal_fr(r, "parse pktype");
	ఒకవేళ (type == 0)
		fail++;
	ఒకవేళ ((r = sshbuf_skip_string(b)) != 0 ||	/* pkalg */
	    (r = sshbuf_skip_string(b)) != 0 ||	/* pkblob */
	    (hostbound && (r = sshkey_froms(b, &hostkey)) != 0))
		fatal_fr(r, "parse pk");
	ఒకవేళ (sshbuf_len(b) != 0)
		fail++;
	sshbuf_free(b);
	ఒకవేళ (hostkey != ఖాళీ) {
		/*
		 * Ensure this is actually one of our hostkeys; unfortunately
		 * can't check ssh->kex->initial_hostkey directly at this point
		 * as packet state has not yet been exported to monitor.
		 */
		ఒకవేళ (get_hostkey_సూచీ(hostkey, 1, ssh) == -1)
			fatal_f("hostbound hostkey does not match");
		sshkey_free(hostkey);
	}
	తిరిగి (fail == 0);
}

స్థిర పూర్ణాంకం
monitor_valid_hostbasedblob(స్థిరరాశి u_char *దత్తాంశం, u_int datalen,
    స్థిరరాశి అక్షరం *cuser, స్థిరరాశి అక్షరం *chost)
{
	నిర్మాణం sshbuf *b;
	స్థిరరాశి u_char *p;
	అక్షరం *cp, *userstyle;
	కొలత_t len;
	పూర్ణాంకం r, fail = 0;
	u_char type;

	ఒకవేళ ((b = sshbuf_from(దత్తాంశం, datalen)) == ఖాళీ)
		fatal_f("sshbuf_new");
	ఒకవేళ ((r = sshbuf_get_string_ప్రత్యక్ష(b, &p, &len)) != 0)
		fatal_fr(r, "parse sessionid");

	ఒకవేళ ((session_id2 == ఖాళీ) ||
	    (len != session_id2_len) ||
	    (timingsafe_bcmp(p, session_id2, session_id2_len) != 0))
		fail++;

	ఒకవేళ ((r = sshbuf_get_u8(b, &type)) != 0)
		fatal_fr(r, "parse type");
	ఒకవేళ (type != SSH2_సందేశం_USERAUTH_REQUEST)
		fail++;
	ఒకవేళ ((r = sshbuf_get_cstring(b, &cp, ఖాళీ)) != 0)
		fatal_fr(r, "parse userstyle");
	xasprintf(&userstyle, "%s%s%s", authctxt->user,
	    authctxt->style ? ":" : "",
	    authctxt->style ? authctxt->style : "");
	ఒకవేళ (strcmp(userstyle, cp) != 0) {
		logit("wrong user name passed to monitor: "
		    "expected %s != %.100s", userstyle, cp);
		fail++;
	}
	విడుదల(userstyle);
	విడుదల(cp);
	ఒకవేళ ((r = sshbuf_skip_string(b)) != 0 ||	/* service */
	    (r = sshbuf_get_cstring(b, &cp, ఖాళీ)) != 0)
		fatal_fr(r, "parse method");
	ఒకవేళ (strcmp(cp, "hostbased") != 0)
		fail++;
	విడుదల(cp);
	ఒకవేళ ((r = sshbuf_skip_string(b)) != 0 ||	/* pkalg */
	    (r = sshbuf_skip_string(b)) != 0)	/* pkblob */
		fatal_fr(r, "parse pk");

	/* verify client host, strip trailing dot if necessary */
	ఒకవేళ ((r = sshbuf_get_cstring(b, &cp, ఖాళీ)) != 0)
		fatal_fr(r, "parse host");
	ఒకవేళ (((len = అక్షరశ్రేణి_పొడవు(cp)) > 0) && cp[len - 1] == '.')
		cp[len - 1] = '\0';
	ఒకవేళ (strcmp(cp, chost) != 0)
		fail++;
	విడుదల(cp);

	/* verify client user */
	ఒకవేళ ((r = sshbuf_get_cstring(b, &cp, ఖాళీ)) != 0)
		fatal_fr(r, "parse ruser");
	ఒకవేళ (strcmp(cp, cuser) != 0)
		fail++;
	విడుదల(cp);

	ఒకవేళ (sshbuf_len(b) != 0)
		fail++;
	sshbuf_free(b);
	తిరిగి (fail == 0);
}

పూర్ణాంకం
mm_answer_keyverify(నిర్మాణం ssh *ssh, పూర్ణాంకం sock, నిర్మాణం sshbuf *m)
{
	నిర్మాణం sshkey *కీలకం;
	స్థిరరాశి u_char *signature, *దత్తాంశం, *blob;
	అక్షరం *sigalg = ఖాళీ, *fp = ఖాళీ;
	కొలత_t signaturelen, datalen, bloblen;
	పూర్ణాంకం r, ret, req_presence = 0, req_verify = 0, valid_దత్తాంశం = 0;
	పూర్ణాంకం encoded_ret;
	నిర్మాణం sshkey_sig_details *sig_details = ఖాళీ;

	ఒకవేళ ((r = sshbuf_get_string_ప్రత్యక్ష(m, &blob, &bloblen)) != 0 ||
	    (r = sshbuf_get_string_ప్రత్యక్ష(m, &signature, &signaturelen)) != 0 ||
	    (r = sshbuf_get_string_ప్రత్యక్ష(m, &దత్తాంశం, &datalen)) != 0 ||
	    (r = sshbuf_get_cstring(m, &sigalg, ఖాళీ)) != 0)
		fatal_fr(r, "parse");

	ఒకవేళ (hostbased_cuser == ఖాళీ || hostbased_chost == ఖాళీ ||
	  !monitor_allowed_కీలకం(blob, bloblen))
		fatal_f("bad key, not previously allowed");

	/* Empty signature algorithm means NULL. */
	ఒకవేళ (*sigalg == '\0') {
		విడుదల(sigalg);
		sigalg = ఖాళీ;
	}

	/* XXX use sshkey_froms here; need to change key_blob, etc. */
	ఒకవేళ ((r = sshkey_from_blob(blob, bloblen, &కీలకం)) != 0)
		fatal_fr(r, "parse key");

	ఎంపిక (కీలకం_blobtype) {
	స్థితి MM_USERKEY:
		valid_దత్తాంశం = monitor_valid_userblob(ssh, దత్తాంశం, datalen);
		auth_పద్ధతి = "publickey";
		ఆపు;
	స్థితి MM_HOSTKEY:
		valid_దత్తాంశం = monitor_valid_hostbasedblob(దత్తాంశం, datalen,
		    hostbased_cuser, hostbased_chost);
		auth_పద్ధతి = "hostbased";
		ఆపు;
	అప్రమేయ:
		valid_దత్తాంశం = 0;
		ఆపు;
	}
	ఒకవేళ (!valid_దత్తాంశం)
		fatal_f("bad %s signature data blob",
		    కీలకం_blobtype == MM_USERKEY ? "userkey" :
		    (కీలకం_blobtype == MM_HOSTKEY ? "hostkey" : "unknown"));

	ఒకవేళ ((fp = sshkey_fingerprint(కీలకం, options.fingerprint_hash,
	    SSH_FP_DEFAULT)) == ఖాళీ)
		fatal_f("sshkey_fingerprint failed");

	ret = sshkey_verify(కీలకం, signature, signaturelen, దత్తాంశం, datalen,
	    sigalg, ssh->compat, &sig_details);
	debug3_f("%s %s signature using %s %s%s%s", auth_పద్ధతి,
	    sshkey_type(కీలకం), sigalg == ఖాళీ ? "default" : sigalg,
	    (ret == 0) ? "verified" : "unverified",
	    (ret != 0) ? ": " : "", (ret != 0) ? ssh_err(ret) : "");

	ఒకవేళ (ret == 0 && కీలకం_blobtype == MM_USERKEY && sig_details != ఖాళీ) {
		req_presence = (options.pubkey_auth_options &
		    PUBKEYAUTH_TOUCH_REQUIRED) ||
		    !కీలకం_opts->no_require_user_presence;
		ఒకవేళ (req_presence &&
		    (sig_details->sk_flags & SSH_SK_USER_PRESENCE_REQD) == 0) {
			error("public key %s %s signature for %s%s from %.128s "
			    "port %d rejected: user presence "
			    "(authenticator touch) requirement not met ",
			    sshkey_type(కీలకం), fp,
			    authctxt->valid ? "" : "invalid user ",
			    authctxt->user, ssh_remote_ipaddr(ssh),
			    ssh_remote_పోర్టు(ssh));
			ret = SSH_ERR_SIGNATURE_INVALID;
		}
		req_verify = (options.pubkey_auth_options &
		    PUBKEYAUTH_VERIFY_REQUIRED) || కీలకం_opts->require_verify;
		ఒకవేళ (req_verify &&
		    (sig_details->sk_flags & SSH_SK_USER_VERIFICATION_REQD) == 0) {
			error("public key %s %s signature for %s%s from %.128s "
			    "port %d rejected: user verification requirement "
			    "not met ", sshkey_type(కీలకం), fp,
			    authctxt->valid ? "" : "invalid user ",
			    authctxt->user, ssh_remote_ipaddr(ssh),
			    ssh_remote_పోర్టు(ssh));
			ret = SSH_ERR_SIGNATURE_INVALID;
		}
	}
	auth2_రికార్డు_కీలకం(authctxt, ret == 0, కీలకం);

	ఒకవేళ (కీలకం_blobtype == MM_USERKEY && ret == 0)
		auth_activate_options(ssh, కీలకం_opts);
	monitor_reset_కీలకం_state();

	sshbuf_reset(m);

	/* encode ret != 0 as positive integer, since we're sending u32 */
	encoded_ret = (ret != 0);
	ఒకవేళ ((r = sshbuf_put_u32(m, encoded_ret)) != 0 ||
	    (r = sshbuf_put_u8(m, sig_details != ఖాళీ)) != 0)
		fatal_fr(r, "assemble");
	ఒకవేళ (sig_details != ఖాళీ) {
		ఒకవేళ ((r = sshbuf_put_u32(m, sig_details->sk_counter)) != 0 ||
		    (r = sshbuf_put_u8(m, sig_details->sk_flags)) != 0)
			fatal_fr(r, "assemble sk");
	}
	sshkey_sig_details_free(sig_details);
	mm_request_send(sock, MONITOR_ANS_KEYVERIFY, m);

	విడుదల(sigalg);
	విడుదల(fp);
	sshkey_free(కీలకం);

	తిరిగి ret == 0;
}

స్థిర శూన్య
mm_రికార్డు_login(నిర్మాణం ssh *ssh, Session *s, నిర్మాణం passwd *pw)
{
	socklen_t fromlen;
	నిర్మాణం sockaddr_storage from;

	/*
	 * Get IP address of client. If the connection is not a socket, let
	 * the address be 0.0.0.0.
	 */
	memset(&from, 0, పరిమాణం(from));
	fromlen = పరిమాణం(from);
	ఒకవేళ (ssh_packet_connection_is_on_socket(ssh)) {
		ఒకవేళ (getpeername(ssh_packet_get_connection_లోపల(ssh),
		    (నిర్మాణం sockaddr *)&from, &fromlen) == -1) {
			debug("getpeername: %.100s", strerror(errno));
			cleanup_exit(255);
		}
	}
	/* Record that there was a login on that tty from the remote host. */
	రికార్డు_login(s->pid, s->tty, pw->pw_name, pw->pw_uid,
	    session_get_remote_name_or_ip(ssh, utmp_len, options.use_dns),
	    (నిర్మాణం sockaddr *)&from, fromlen);
}

స్థిర శూన్య
mm_session_close(Session *s)
{
	debug3_f("session %d pid %ld", s->self, (దీర్ఘ)s->pid);
	ఒకవేళ (s->ttyfd != -1) {
		debug3_f("tty %s ptyfd %d", s->tty, s->ptyfd);
		session_pty_cleanup2(s);
	}
	session_వాడని(s->self);
}

పూర్ణాంకం
mm_answer_pty(నిర్మాణం ssh *ssh, పూర్ణాంకం sock, నిర్మాణం sshbuf *m)
{
	బాహ్య నిర్మాణం monitor *pmonitor;
	Session *s;
	పూర్ణాంకం r, res, fd0;

	debug3_f("entering");

	sshbuf_reset(m);
	s = session_new();
	ఒకవేళ (s == ఖాళీ)
		వెళ్ళు error;
	s->authctxt = authctxt;
	s->pw = authctxt->pw;
	s->pid = pmonitor->m_pid;
	res = pty_allocate(&s->ptyfd, &s->ttyfd, s->tty, పరిమాణం(s->tty));
	ఒకవేళ (res == 0)
		వెళ్ళు error;
	pty_setowner(authctxt->pw, s->tty);

	ఒకవేళ ((r = sshbuf_put_u32(m, 1)) != 0 ||
	    (r = sshbuf_put_cstring(m, s->tty)) != 0)
		fatal_fr(r, "assemble");

	/* We need to trick ttyslot */
	ఒకవేళ (dup2(s->ttyfd, 0) == -1)
		fatal_f("dup2");

	mm_రికార్డు_login(ssh, s, authctxt->pw);

	/* Now we can close the file descriptor again */
	close(0);

	/* send messages generated by record_login */
	ఒకవేళ ((r = sshbuf_put_stringb(m, loginmsg)) != 0)
		fatal_fr(r, "assemble loginmsg");
	sshbuf_reset(loginmsg);

	mm_request_send(sock, MONITOR_ANS_PTY, m);

	ఒకవేళ (mm_send_fd(sock, s->ptyfd) == -1 ||
	    mm_send_fd(sock, s->ttyfd) == -1)
		fatal_f("send fds failed");

	/* make sure nothing uses fd 0 */
	ఒకవేళ ((fd0 = open(_PATH_DEVNULL, O_RDONLY)) == -1)
		fatal_f("open(/dev/null): %s", strerror(errno));
	ఒకవేళ (fd0 != 0)
		error_f("fd0 %d != 0", fd0);

	/* slave side of pty is not needed */
	close(s->ttyfd);
	s->ttyfd = s->ptyfd;
	/* no need to dup() because nobody closes ptyfd */
	s->ptymaster = s->ptyfd;

	debug3_f("tty %s ptyfd %d", s->tty, s->ttyfd);

	తిరిగి (0);

 error:
	ఒకవేళ (s != ఖాళీ)
		mm_session_close(s);
	ఒకవేళ ((r = sshbuf_put_u32(m, 0)) != 0)
		fatal_fr(r, "assemble 0");
	mm_request_send(sock, MONITOR_ANS_PTY, m);
	తిరిగి (0);
}

పూర్ణాంకం
mm_answer_pty_cleanup(నిర్మాణం ssh *ssh, పూర్ణాంకం sock, నిర్మాణం sshbuf *m)
{
	Session *s;
	అక్షరం *tty;
	పూర్ణాంకం r;

	debug3_f("entering");

	ఒకవేళ ((r = sshbuf_get_cstring(m, &tty, ఖాళీ)) != 0)
		fatal_fr(r, "parse tty");
	ఒకవేళ ((s = session_by_tty(tty)) != ఖాళీ)
		mm_session_close(s);
	sshbuf_reset(m);
	విడుదల(tty);
	తిరిగి (0);
}

పూర్ణాంకం
mm_answer_పదం(నిర్మాణం ssh *ssh, పూర్ణాంకం sock, నిర్మాణం sshbuf *req)
{
	బాహ్య నిర్మాణం monitor *pmonitor;
	పూర్ణాంకం res, స్థితి_2;

	debug3_f("tearing down sessions");

	/* The child is terminating */
	session_destroy_all(ssh, &mm_session_close);

#నిర్వచితమైతే USE_PAM
	ఒకవేళ (options.use_pam)
		sshpam_cleanup();
#అయితే_ముగింపు

	అయితే (waitpid(pmonitor->m_pid, &స్థితి_2, 0) == -1)
		ఒకవేళ (errno != EINTR)
			నిష్క్రమించు(1);

	res = WIFEXITED(స్థితి_2) ? WEXITSTATUS(స్థితి_2) : 1;

	/* Terminate process */
	నిష్క్రమించు(res);
}

#నిర్వచితమైతే SSH_AUDIT_EVENTS
/* Report that an audit event occurred */
పూర్ణాంకం
mm_answer_audit_event(నిర్మాణం ssh *ssh, పూర్ణాంకం socket, నిర్మాణం sshbuf *m)
{
	u_int n;
	ssh_audit_event_t event;
	పూర్ణాంకం r;

	debug3_f("entering");

	ఒకవేళ ((r = sshbuf_get_u32(m, &n)) != 0)
		fatal_fr(r, "buffer error");
	event = (ssh_audit_event_t)n;
	ఎంపిక (event) {
	స్థితి SSH_AUTH_FAIL_PUBKEY:
	స్థితి SSH_AUTH_FAIL_HOSTBASED:
	స్థితి SSH_AUTH_FAIL_GSSAPI:
	స్థితి SSH_LOGIN_EXCEED_MAXTRIES:
	స్థితి SSH_LOGIN_మూలం_DENIED:
	స్థితి SSH_CONNECTION_CLOSE:
	స్థితి SSH_INVALID_USER:
		audit_event(ssh, event);
		ఆపు;
	అప్రమేయ:
		fatal("Audit event type %d not permitted", event);
	}

	తిరిగి (0);
}

పూర్ణాంకం
mm_answer_audit_command(నిర్మాణం ssh *ssh, పూర్ణాంకం socket, నిర్మాణం sshbuf *m)
{
	అక్షరం *cmd;
	పూర్ణాంకం r;

	debug3_f("entering");
	ఒకవేళ ((r = sshbuf_get_cstring(m, &cmd, ఖాళీ)) != 0)
		fatal_fr(r, "buffer error");
	/* sanity check command, if so how? */
	audit_నిరంతరం_command(cmd);
	విడుదల(cmd);
	తిరిగి (0);
}
#అయితే_ముగింపు /* SSH_AUDIT_EVENTS */

శూన్య
monitor_clear_keystate(నిర్మాణం ssh *ssh, నిర్మాణం monitor *pmonitor)
{
	ssh_clear_newkeys(ssh, బహుళకం_లోపల);
	ssh_clear_newkeys(ssh, బహుళకం_బహిర్గతం);
	sshbuf_free(బిడ్డ_state);
	బిడ్డ_state = ఖాళీ;
}

శూన్య
monitor_apply_keystate(నిర్మాణం ssh *ssh, నిర్మాణం monitor *pmonitor)
{
	నిర్మాణం kex *kex;
	పూర్ణాంకం r;

	debug3_f("packet_set_state");
	ఒకవేళ ((r = ssh_packet_సమితి_state(ssh, బిడ్డ_state)) != 0)
		fatal_fr(r, "packet_set_state");
	sshbuf_free(బిడ్డ_state);
	బిడ్డ_state = ఖాళీ;
	ఒకవేళ ((kex = ssh->kex) == ఖాళీ)
		fatal_f("internal error: ssh->kex == NULL");
	ఒకవేళ (session_id2_len != sshbuf_len(ssh->kex->session_id)) {
		fatal_f("incorrect session id length %zu (expected %u)",
		    sshbuf_len(ssh->kex->session_id), session_id2_len);
	}
	ఒకవేళ (memcmp(sshbuf_ptr(ssh->kex->session_id), session_id2,
	    session_id2_len) != 0)
		fatal_f("session ID mismatch");
	/* XXX set callbacks */
#నిర్వచితమైతే WITH_OPENSSL
	kex->kex[KEX_DH_GRP1_SHA1] = kex_gen_server;
	kex->kex[KEX_DH_GRP14_SHA1] = kex_gen_server;
	kex->kex[KEX_DH_GRP14_SHA256] = kex_gen_server;
	kex->kex[KEX_DH_GRP16_SHA512] = kex_gen_server;
	kex->kex[KEX_DH_GRP18_SHA512] = kex_gen_server;
	kex->kex[KEX_DH_GEX_SHA1] = kexgex_server;
	kex->kex[KEX_DH_GEX_SHA256] = kexgex_server;
	kex->kex[KEX_ECDH_SHA2] = kex_gen_server;
	kex->kex[KEX_KEM_MLKEM768ECDH_SHA256] = kex_gen_server;
#అయితే_ముగింపు
	kex->kex[KEX_C25519_SHA256] = kex_gen_server;
	kex->kex[KEX_KEM_SNTRUP761X25519_SHA512] = kex_gen_server;
	kex->kex[KEX_KEM_MLKEM768X25519_SHA256] = kex_gen_server;
	kex->ఎక్కించు_host_ప్రజా_కీలకం=&get_hostkey_ప్రజా_by_type;
	kex->ఎక్కించు_host_వ్యక్తిగత_కీలకం=&get_hostkey_వ్యక్తిగత_by_type;
	kex->host_కీలకం_సూచీ=&get_hostkey_సూచీ;
	kex->sign = sshd_hostkey_sign;
}

/* This function requires careful sanity checking */

శూన్య
mm_get_keystate(నిర్మాణం ssh *ssh, నిర్మాణం monitor *pmonitor)
{
	debug3_f("Waiting for new keys");

	ఒకవేళ ((బిడ్డ_state = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");
	mm_request_receive_expect(pmonitor->m_sendfd, MONITOR_REQ_KEYEXPORT,
	    బిడ్డ_state);
	debug3_f("GOT new keys");
}


/* XXX */

స్థిర శూన్య
monitor_openfds(నిర్మాణం monitor *mon, పూర్ణాంకం do_logfds)
{
	పూర్ణాంకం pair[2];
#నిర్వచితమైతే SO_ZEROIZE
	పూర్ణాంకం on = 1;
#అయితే_ముగింపు

	ఒకవేళ (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == -1)
		fatal_f("socketpair: %s", strerror(errno));
#నిర్వచితమైతే SO_ZEROIZE
	ఒకవేళ (setsockopt(pair[0], SOL_SOCKET, SO_ZEROIZE, &on, పరిమాణం(on)) == -1)
		error("setsockopt SO_ZEROIZE(0): %.100s", strerror(errno));
	ఒకవేళ (setsockopt(pair[1], SOL_SOCKET, SO_ZEROIZE, &on, పరిమాణం(on)) == -1)
		error("setsockopt SO_ZEROIZE(1): %.100s", strerror(errno));
#అయితే_ముగింపు
	FD_CLOSEONEXEC(pair[0]);
	FD_CLOSEONEXEC(pair[1]);
	mon->m_recvfd = pair[0];
	mon->m_sendfd = pair[1];

	ఒకవేళ (do_logfds) {
		ఒకవేళ (pipe(pair) == -1)
			fatal_f("pipe: %s", strerror(errno));
		FD_CLOSEONEXEC(pair[0]);
		FD_CLOSEONEXEC(pair[1]);
		mon->m_log_recvfd = pair[0];
		mon->m_log_sendfd = pair[1];
	} లేకపోతే
		mon->m_log_recvfd = mon->m_log_sendfd = -1;
}

నిర్మాణం monitor *
monitor_init(శూన్య)
{
	నిర్మాణం monitor *mon;

	mon = xcalloc(1, పరిమాణం(*mon));
	monitor_openfds(mon, 1);

	తిరిగి mon;
}

శూన్య
monitor_reinit(నిర్మాణం monitor *mon)
{
	monitor_openfds(mon, 0);
}

పూర్ణాంకం
monitor_auth_attempted(శూన్య)
{
	తిరిగి auth_attempted;
}

పూర్ణాంకం
monitor_invalid_user(శూన్య)
{
	తిరిగి invalid_user;
}

#నిర్వచితమైతే GSSAPI
పూర్ణాంకం
mm_answer_gss_అమరిక_ctx(నిర్మాణం ssh *ssh, పూర్ణాంకం sock, నిర్మాణం sshbuf *m)
{
	gss_OID_desc goid;
	OM_uint32 major;
	కొలత_t len;
	u_char *p;
	పూర్ణాంకం r;

	ఒకవేళ (!options.gss_authentication)
		fatal_f("GSSAPI authentication not enabled");

	ssh_gssapi_cleanup_global_client();

	ఒకవేళ ((r = sshbuf_get_string(m, &p, &len)) != 0)
		fatal_fr(r, "parse");
	goid.elements = p;
	goid.నిడివి = len;

	major = ssh_gssapi_server_ctx(&gsscontext, &goid);

	విడుదల(goid.elements);

	sshbuf_reset(m);
	ఒకవేళ ((r = sshbuf_put_u32(m, major)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(sock, MONITOR_ANS_GSSSETUP, m);

	/* Now we have a context, enable the step */
	monitor_permit(mon_dispatch, MONITOR_REQ_GSSSTEP, 1);

	తిరిగి (0);
}

పూర్ణాంకం
mm_answer_gss_accept_ctx(నిర్మాణం ssh *ssh, పూర్ణాంకం sock, నిర్మాణం sshbuf *m)
{
	gss_బఫరు_desc లోపల;
	gss_బఫరు_desc బహిర్గతం = GSS_C_ఖాళీలు_బఫరు;
	OM_uint32 major, minor;
	OM_uint32 flags = 0; /* GSI needs this */
	పూర్ణాంకం r;

	ఒకవేళ (!options.gss_authentication)
		fatal_f("GSSAPI authentication not enabled");

	ఒకవేళ ((r = ssh_gssapi_get_బఫరు_desc(m, &లోపల)) != 0)
		fatal_fr(r, "ssh_gssapi_get_buffer_desc");
	major = ssh_gssapi_accept_ctx(gsscontext, &లోపల, &బహిర్గతం, &flags);
	విడుదల(లోపల.విలువ);

	sshbuf_reset(m);
	ఒకవేళ ((r = sshbuf_put_u32(m, major)) != 0 ||
	    (r = sshbuf_put_string(m, బహిర్గతం.విలువ, బహిర్గతం.నిడివి)) != 0 ||
	    (r = sshbuf_put_u32(m, flags)) != 0)
		fatal_fr(r, "assemble");
	mm_request_send(sock, MONITOR_ANS_GSSSTEP, m);

	gss_release_బఫరు(&minor, &బహిర్గతం);

	ఒకవేళ (major == GSS_S_COMPLETE) {
		monitor_permit(mon_dispatch, MONITOR_REQ_GSSSTEP, 0);
		monitor_permit(mon_dispatch, MONITOR_REQ_GSSUSEROK, 1);
		monitor_permit(mon_dispatch, MONITOR_REQ_GSSCHECKMIC, 1);
	}
	తిరిగి (0);
}

పూర్ణాంకం
mm_answer_gss_checkmic(నిర్మాణం ssh *ssh, పూర్ణాంకం sock, నిర్మాణం sshbuf *m)
{
	gss_బఫరు_desc gssbuf, mic;
	OM_uint32 ret;
	పూర్ణాంకం r;

	ఒకవేళ (!options.gss_authentication)
		fatal_f("GSSAPI authentication not enabled");

	ఒకవేళ ((r = ssh_gssapi_get_బఫరు_desc(m, &gssbuf)) != 0 ||
	    (r = ssh_gssapi_get_బఫరు_desc(m, &mic)) != 0)
		fatal_fr(r, "ssh_gssapi_get_buffer_desc");

	ret = ssh_gssapi_checkmic(gsscontext, &gssbuf, &mic);

	విడుదల(gssbuf.విలువ);
	విడుదల(mic.విలువ);

	sshbuf_reset(m);
	ఒకవేళ ((r = sshbuf_put_u32(m, ret)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(sock, MONITOR_ANS_GSSCHECKMIC, m);

	ఒకవేళ (!GSS_ERROR(ret))
		monitor_permit(mon_dispatch, MONITOR_REQ_GSSUSEROK, 1);

	తిరిగి (0);
}

పూర్ణాంకం
mm_answer_gss_userok(నిర్మాణం ssh *ssh, పూర్ణాంకం sock, నిర్మాణం sshbuf *m)
{
	పూర్ణాంకం r, authenticated;
	స్థిరరాశి అక్షరం *displayname;

	ఒకవేళ (!options.gss_authentication)
		fatal_f("GSSAPI authentication not enabled");

	authenticated = authctxt->valid && ssh_gssapi_userok(authctxt->user);

	sshbuf_reset(m);
	ఒకవేళ ((r = sshbuf_put_u32(m, authenticated)) != 0)
		fatal_fr(r, "assemble");

	debug3_f("sending result %d", authenticated);
	mm_request_send(sock, MONITOR_ANS_GSSUSEROK, m);

	auth_పద్ధతి = "gssapi-with-mic";

	ఒకవేళ ((displayname = ssh_gssapi_displayname()) != ఖాళీ)
		auth2_రికార్డు_info(authctxt, "%s", displayname);

	/* Monitor loop will terminate if authenticated */
	తిరిగి (authenticated);
}
#అయితే_ముగింపు /* GSSAPI */

