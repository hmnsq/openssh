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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <sys/wait.h>
#અન્તર્ભાવ <sys/socket.h>
#અન્તર્ભાવ <sys/tree.h>
#અન્તર્ભાવ <sys/queue.h>

#અન્તર્ભાવ <errno.h>
#અન્તર્ભાવ <fcntl.h>
#અન્તર્ભાવ <limits.h>
#અન્તર્ભાવ <paths.h>
#અન્તર્ભાવ <poll.h>
#અન્તર્ભાવ <pwd.h>
#અન્તર્ભાવ <signal.h>
#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <stdint.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <unistd.h>

#ifdef WITH_OPENSSL
#અન્તર્ભાવ <openssl/dh.h>
#endif

#અન્તર્ભાવ "openbsd-compat/openssl-compat.h"

#અન્તર્ભાવ "atomicio.h"
#અન્તર્ભાવ "xmalloc.h"
#અન્તર્ભાવ "ssh.h"
#અન્તર્ભાવ "sshkey.h"
#અન્તર્ભાવ "sshbuf.h"
#અન્તર્ભાવ "hostfile.h"
#અન્તર્ભાવ "auth.h"
#અન્તર્ભાવ "cipher.h"
#અન્તર્ભાવ "kex.h"
#અન્તર્ભાવ "dh.h"
#અન્તર્ભાવ "auth-pam.h"
#અન્તર્ભાવ "packet.h"
#અન્તર્ભાવ "auth-options.h"
#અન્તર્ભાવ "sshpty.h"
#અન્તર્ભાવ "channels.h"
#અન્તર્ભાવ "session.h"
#અન્તર્ભાવ "sshlogin.h"
#અન્તર્ભાવ "canohost.h"
#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "misc.h"
#અન્તર્ભાવ "servconf.h"
#અન્તર્ભાવ "monitor.h"
#ifdef GSSAPI
#અન્તર્ભાવ "ssh-gss.h"
#endif
#અન્તર્ભાવ "monitor_wrap.h"
#અન્તર્ભાવ "monitor_fdpass.h"
#અન્તર્ભાવ "compat.h"
#અન્તર્ભાવ "ssh2.h"
#અન્તર્ભાવ "authfd.h"
#અન્તર્ભાવ "match.h"
#અન્તર્ભાવ "ssherr.h"
#અન્તર્ભાવ "sk-api.h"
#અન્તર્ભાવ "srclimit.h"

#ifdef GSSAPI
સ્થિર Gssctxt *gsscontext = ખાલી;
#endif

/* Imports */
બાહ્ય ServerOptions options;
બાહ્ય u_int utmp_len;
બાહ્ય સંરચના sshbuf *cfg;
બાહ્ય સંરચના sshbuf *loginmsg;
બાહ્ય સંરચના include_list includes;
બાહ્ય સંરચના sshauthopt *auth_opts; /* XXX move to permanent ssh->authctxt? */

/* State exported from the child */
સ્થિર સંરચના sshbuf *child_state;

/* Functions on the monitor that answer unprivileged requests */

પૂર્ણાંક mm_answer_moduli(સંરચના ssh *, પૂર્ણાંક, સંરચના sshbuf *);
પૂર્ણાંક mm_answer_setcompat(સંરચના ssh *, પૂર્ણાંક, સંરચના sshbuf *);
પૂર્ણાંક mm_answer_sign(સંરચના ssh *, પૂર્ણાંક, સંરચના sshbuf *);
પૂર્ણાંક mm_answer_pwnamallow(સંરચના ssh *, પૂર્ણાંક, સંરચના sshbuf *);
પૂર્ણાંક mm_answer_auth2_read_banner(સંરચના ssh *, પૂર્ણાંક, સંરચના sshbuf *);
પૂર્ણાંક mm_answer_authserv(સંરચના ssh *, પૂર્ણાંક, સંરચના sshbuf *);
પૂર્ણાંક mm_answer_authpassword(સંરચના ssh *, પૂર્ણાંક, સંરચના sshbuf *);
પૂર્ણાંક mm_answer_bsdauthquery(સંરચના ssh *, પૂર્ણાંક, સંરચના sshbuf *);
પૂર્ણાંક mm_answer_bsdauthrespond(સંરચના ssh *, પૂર્ણાંક, સંરચના sshbuf *);
પૂર્ણાંક mm_answer_keyallowed(સંરચના ssh *, પૂર્ણાંક, સંરચના sshbuf *);
પૂર્ણાંક mm_answer_keyverify(સંરચના ssh *, પૂર્ણાંક, સંરચના sshbuf *);
પૂર્ણાંક mm_answer_pty(સંરચના ssh *, પૂર્ણાંક, સંરચના sshbuf *);
પૂર્ણાંક mm_answer_pty_cleanup(સંરચના ssh *, પૂર્ણાંક, સંરચના sshbuf *);
પૂર્ણાંક mm_answer_term(સંરચના ssh *, પૂર્ણાંક, સંરચના sshbuf *);
પૂર્ણાંક mm_answer_state(સંરચના ssh *, પૂર્ણાંક, સંરચના sshbuf *);

#ifdef USE_PAM
પૂર્ણાંક mm_answer_pam_start(સંરચના ssh *, પૂર્ણાંક, સંરચના sshbuf *);
પૂર્ણાંક mm_answer_pam_account(સંરચના ssh *, પૂર્ણાંક, સંરચના sshbuf *);
પૂર્ણાંક mm_answer_pam_init_ctx(સંરચના ssh *, પૂર્ણાંક, સંરચના sshbuf *);
પૂર્ણાંક mm_answer_pam_query(સંરચના ssh *, પૂર્ણાંક, સંરચના sshbuf *);
પૂર્ણાંક mm_answer_pam_respond(સંરચના ssh *, પૂર્ણાંક, સંરચના sshbuf *);
પૂર્ણાંક mm_answer_pam_free_ctx(સંરચના ssh *, પૂર્ણાંક, સંરચના sshbuf *);
#endif

#ifdef GSSAPI
પૂર્ણાંક mm_answer_gss_setup_ctx(સંરચના ssh *, પૂર્ણાંક, સંરચના sshbuf *);
પૂર્ણાંક mm_answer_gss_accept_ctx(સંરચના ssh *, પૂર્ણાંક, સંરચના sshbuf *);
પૂર્ણાંક mm_answer_gss_userok(સંરચના ssh *, પૂર્ણાંક, સંરચના sshbuf *);
પૂર્ણાંક mm_answer_gss_checkmic(સંરચના ssh *, પૂર્ણાંક, સંરચના sshbuf *);
#endif

#ifdef SSH_AUDIT_EVENTS
પૂર્ણાંક mm_answer_audit_event(સંરચના ssh *, પૂર્ણાંક, સંરચના sshbuf *);
પૂર્ણાંક mm_answer_audit_command(સંરચના ssh *, પૂર્ણાંક, સંરચના sshbuf *);
#endif

સ્થિર Authctxt *authctxt;

/* local state for key verify */
સ્થિર u_char *ચાવી_blob = ખાલી;
સ્થિર size_t ચાવી_bloblen = 0;
સ્થિર u_int ચાવી_blobtype = MM_NOKEY;
સ્થિર સંરચના sshauthopt *ચાવી_opts = ખાલી;
સ્થિર અક્ષર *hostbased_cuser = ખાલી;
સ્થિર અક્ષર *hostbased_chost = ખાલી;
સ્થિર અક્ષર *auth_method = "unknown";
સ્થિર અક્ષર *auth_submethod = ખાલી;
સ્થિર u_int session_id2_len = 0;
સ્થિર u_char *session_id2 = ખાલી;
સ્થિર pid_t monitor_child_pid;
સ્થિર પૂર્ણાંક auth_attempted = 0;
સ્થિર પૂર્ણાંક invalid_user = 0;
સ્થિર પૂર્ણાંક compat_set = 0;

સંરચના mon_table {
	ગણના monitor_reqtype type;
	પૂર્ણાંક flags;
	પૂર્ણાંક (*f)(સંરચના ssh *, પૂર્ણાંક, સંરચના sshbuf *);
};

#define MON_ISAUTH	0x0004	/* Required for Authentication */
#define MON_AUTHDECIDE	0x0008	/* Decides Authentication */
#define MON_ONCE	0x0010	/* Disable after calling */
#define MON_ALOG	0x0020	/* Log auth attempt without authenticating */

#define MON_AUTH	(MON_ISAUTH|MON_AUTHDECIDE)

#define MON_PERMIT	0x1000	/* Request is permitted */

સ્થિર પૂર્ણાંક monitor_read(સંરચના ssh *, સંરચના monitor *, સંરચના mon_table *,
    સંરચના mon_table **);
સ્થિર પૂર્ણાંક monitor_read_log(સંરચના monitor *);

સંરચના mon_table mon_dispatch_proto20[] = {
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
    {0, 0, ખાલી}
};

સંરચના mon_table mon_dispatch_postauth20[] = {
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
    {0, 0, ખાલી}
};

સંરચના mon_table *mon_dispatch;

/* Specifies if a certain message is allowed at the moment */
સ્થિર શૂન્ય
monitor_permit(સંરચના mon_table *ent, ગણના monitor_reqtype type, પૂર્ણાંક permit)
{
	જ્યારે (ent->f != ખાલી) {
		જો (ent->type == type) {
			ent->flags &= ~MON_PERMIT;
			ent->flags |= permit ? MON_PERMIT : 0;
			પાછા;
		}
		ent++;
	}
}

સ્થિર શૂન્ય
monitor_permit_authentications(પૂર્ણાંક permit)
{
	સંરચના mon_table *ent = mon_dispatch;

	જ્યારે (ent->f != ખાલી) {
		જો (ent->flags & MON_AUTH) {
			ent->flags &= ~MON_PERMIT;
			ent->flags |= permit ? MON_PERMIT : 0;
		}
		ent++;
	}
}

શૂન્ય
monitor_child_preauth(સંરચના ssh *ssh, સંરચના monitor *pmonitor)
{
	સંરચના mon_table *ent;
	પૂર્ણાંક status, authenticated = 0, partial = 0;

	debug3("preauth child monitor started");

	જો (pmonitor->m_recvfd >= 0)
		close(pmonitor->m_recvfd);
	જો (pmonitor->m_log_sendfd >= 0)
		close(pmonitor->m_log_sendfd);
	pmonitor->m_log_sendfd = pmonitor->m_recvfd = -1;

	authctxt = (Authctxt *)ssh->authctxt;
	memset(authctxt, 0, કદ(*authctxt));
	ssh->authctxt = authctxt;

	authctxt->loginmsg = loginmsg;

	mon_dispatch = mon_dispatch_proto20;
	/* Permit requests for state, moduli and signatures */
	monitor_permit(mon_dispatch, MONITOR_REQ_STATE, 1);
	monitor_permit(mon_dispatch, MONITOR_REQ_MODULI, 1);
	monitor_permit(mon_dispatch, MONITOR_REQ_SETCOMPAT, 1);
	monitor_permit(mon_dispatch, MONITOR_REQ_SIGN, 1);

	/* The first few requests do not require asynchronous access */
	જ્યારે (!authenticated) {
		partial = 0;
		auth_method = "unknown";
		auth_submethod = ખાલી;
		auth2_authctxt_reset_info(authctxt);

		authenticated = (monitor_read(ssh, pmonitor,
		    mon_dispatch, &ent) == 1);

		/* Record that auth was attempted to set exit status later */
		જો ((ent->flags & MON_AUTH) != 0)
			auth_attempted = 1;

		/* Special handling for multiple required authentications */
		જો (options.અંક_auth_methods != 0) {
			જો (authenticated &&
			    !auth2_update_methods_lists(authctxt,
			    auth_method, auth_submethod)) {
				debug3_f("method %s: partial", auth_method);
				authenticated = 0;
				partial = 1;
			}
		}

		જો (authenticated) {
			જો (!(ent->flags & MON_AUTHDECIDE))
				fatal_f("unexpected authentication from %d",
				    ent->type);
			જો (authctxt->pw->pw_uid == 0 &&
			    !auth_મૂળ_allowed(ssh, auth_method))
				authenticated = 0;
#ifdef USE_PAM
			/* PAM needs to perform account checks after auth */
			જો (options.use_pam && authenticated) {
				સંરચના sshbuf *m;

				જો ((m = sshbuf_new()) == ખાલી)
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
		જો (ent->flags & (MON_AUTHDECIDE|MON_ALOG)) {
			auth_log(ssh, authenticated, partial,
			    auth_method, auth_submethod);
			જો (!partial && !authenticated)
				authctxt->failures++;
			જો (authenticated || partial) {
				auth2_update_session_info(authctxt,
				    auth_method, auth_submethod);
			}
		}
		જો (authctxt->failures > options.max_authtries) {
			/* Shouldn't happen */
			fatal_f("privsep child made too many authentication "
			    "attempts");
		}
	}

	જો (!authctxt->valid)
		fatal_f("authenticated invalid user");
	જો (strcmp(auth_method, "unknown") == 0)
		fatal_f("authentication method name unknown");

	debug_f("user %s authenticated by privileged process", authctxt->user);
	auth_attempted = 0;
	ssh->authctxt = ખાલી;
	ssh_packet_set_log_preamble(ssh, "user %s", authctxt->user);

	mm_get_keystate(ssh, pmonitor);

	/* Drain any buffered messages from the child */
	જ્યારે (pmonitor->m_log_recvfd != -1 && monitor_read_log(pmonitor) == 0)
		;

	/* Wait for the child's exit status */
	જ્યારે (waitpid(pmonitor->m_pid, &status, 0) == -1) {
		જો (errno == EINTR)
			ચાલુ;
		fatal_f("waitpid: %s", strerror(errno));
	}
	જો (WIFEXITED(status)) {
		જો (WEXITSTATUS(status) != 0)
			fatal_f("preauth child %ld exited with status %d",
			    (long)pmonitor->m_pid, WEXITSTATUS(status));
	} નહીંતર જો (WIFSIGNALED(status)) {
		fatal_f("preauth child %ld terminated by signal %d",
		    (long)pmonitor->m_pid, WTERMSIG(status));
	}
	debug3_f("preauth child %ld terminated successfully",
	    (long)pmonitor->m_pid);

	જો (pmonitor->m_recvfd >= 0)
		close(pmonitor->m_recvfd);
	જો (pmonitor->m_log_sendfd >= 0)
		close(pmonitor->m_log_sendfd);
	pmonitor->m_sendfd = pmonitor->m_log_recvfd = -1;
	pmonitor->m_pid = -1;
}

સ્થિર શૂન્ય
monitor_set_child_handler(pid_t pid)
{
	monitor_child_pid = pid;
}

સ્થિર શૂન્ય
monitor_child_handler(પૂર્ણાંક sig)
{
	kill(monitor_child_pid, sig);
}

શૂન્ય
monitor_child_postauth(સંરચના ssh *ssh, સંરચના monitor *pmonitor)
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

	જો (auth_opts->permit_pty_flag) {
		monitor_permit(mon_dispatch, MONITOR_REQ_PTY, 1);
		monitor_permit(mon_dispatch, MONITOR_REQ_PTYCLEANUP, 1);
	}

	માટે (;;)
		monitor_read(ssh, pmonitor, mon_dispatch, ખાલી);
}

સ્થિર પૂર્ણાંક
monitor_read_log(સંરચના monitor *pmonitor)
{
	સંરચના sshbuf *logmsg;
	u_int len, level, forced;
	અક્ષર *સંદેશ;
	u_char *p;
	પૂર્ણાંક r;

	જો ((logmsg = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new");

	/* Read length */
	જો ((r = sshbuf_reserve(logmsg, 4, &p)) != 0)
		fatal_fr(r, "reserve len");
	જો (atomicio(પઠ, pmonitor->m_log_recvfd, p, 4) != 4) {
		જો (errno == EPIPE) {
			sshbuf_free(logmsg);
			debug_f("child log fd closed");
			close(pmonitor->m_log_recvfd);
			pmonitor->m_log_recvfd = -1;
			પાછા -1;
		}
		fatal_f("log fd read: %s", strerror(errno));
	}
	જો ((r = sshbuf_get_u32(logmsg, &len)) != 0)
		fatal_fr(r, "parse len");
	જો (len <= 4 || len > 8192)
		fatal_f("invalid log message length %u", len);

	/* Read severity, message */
	sshbuf_reset(logmsg);
	જો ((r = sshbuf_reserve(logmsg, len, &p)) != 0)
		fatal_fr(r, "reserve msg");
	જો (atomicio(પઠ, pmonitor->m_log_recvfd, p, len) != len)
		fatal_f("log fd read: %s", strerror(errno));
	જો ((r = sshbuf_get_u32(logmsg, &level)) != 0 ||
	    (r = sshbuf_get_u32(logmsg, &forced)) != 0 ||
	    (r = sshbuf_get_cstring(logmsg, &સંદેશ, ખાલી)) != 0)
		fatal_fr(r, "parse");

	/* Log it */
	જો (log_level_name(level) == ખાલી)
		fatal_f("invalid log level %u (corrupted message?)", level);
	sshlogdirect(level, forced, "%s [%s]", સંદેશ,
	    mon_dispatch == mon_dispatch_postauth20 ? "postauth" : "preauth");

	sshbuf_free(logmsg);
	મુક્ત(સંદેશ);

	પાછા 0;
}

સ્થિર પૂર્ણાંક
monitor_read(સંરચના ssh *ssh, સંરચના monitor *pmonitor, સંરચના mon_table *ent,
    સંરચના mon_table **pent)
{
	સંરચના sshbuf *m;
	પૂર્ણાંક r, ret;
	u_char type;
	સંરચના pollfd pfd[2];

	માટે (;;) {
		memset(&pfd, 0, કદ(pfd));
		pfd[0].fd = pmonitor->m_sendfd;
		pfd[0].events = POLLIN;
		pfd[1].fd = pmonitor->m_log_recvfd;
		pfd[1].events = pfd[1].fd == -1 ? 0 : POLLIN;
		જો (poll(pfd, pfd[1].fd == -1 ? 1 : 2, -1) == -1) {
			જો (errno == EINTR || errno == EAGAIN)
				ચાલુ;
			fatal_f("poll: %s", strerror(errno));
		}
		જો (pfd[1].revents) {
			/*
			 * Drain all log messages before processing next
			 * monitor request.
			 */
			monitor_read_log(pmonitor);
			ચાલુ;
		}
		જો (pfd[0].revents)
			તોડો;  /* Continues below */
	}

	જો ((m = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new");

	mm_request_receive(pmonitor->m_sendfd, m);
	જો ((r = sshbuf_get_u8(m, &type)) != 0)
		fatal_fr(r, "parse type");

	debug3_f("checking request %d", type);

	જ્યારે (ent->f != ખાલી) {
		જો (ent->type == type)
			તોડો;
		ent++;
	}

	જો (ent->f != ખાલી) {
		જો (!(ent->flags & MON_PERMIT))
			fatal_f("unpermitted request %d", type);
		ret = (*ent->f)(ssh, pmonitor->m_sendfd, m);
		sshbuf_free(m);

		/* The child may use this request only once, disable it */
		જો (ent->flags & MON_ONCE) {
			debug2_f("%d used once, disabling now", type);
			ent->flags &= ~MON_PERMIT;
		}

		જો (pent != ખાલી)
			*pent = ent;

		પાછા ret;
	}

	fatal_f("unsupported request: %d", type);

	/* NOTREACHED */
	પાછા (-1);
}

/* allowed key state */
સ્થિર પૂર્ણાંક
monitor_allowed_ચાવી(અચલ u_char *blob, u_int bloblen)
{
	/* make sure key is allowed */
	જો (ચાવી_blob == ખાલી || ચાવી_bloblen != bloblen ||
	    timingsafe_bcmp(ચાવી_blob, blob, ચાવી_bloblen))
		પાછા (0);
	પાછા (1);
}

સ્થિર શૂન્ય
monitor_reset_ચાવી_state(શૂન્ય)
{
	/* reset state */
	મુક્ત(ચાવી_blob);
	મુક્ત(hostbased_cuser);
	મુક્ત(hostbased_chost);
	sshauthopt_free(ચાવી_opts);
	ચાવી_blob = ખાલી;
	ચાવી_bloblen = 0;
	ચાવી_blobtype = MM_NOKEY;
	ચાવી_opts = ખાલી;
	hostbased_cuser = ખાલી;
	hostbased_chost = ખાલી;
}

પૂર્ણાંક
mm_answer_state(સંરચના ssh *ssh, પૂર્ણાંક sock, સંરચના sshbuf *unused)
{
	સંરચના sshbuf *m = ખાલી, *config = ખાલી, *hostkeys = ખાલી;
	સંરચના sshbuf *opts = ખાલી, *confdata = ખાલી;
	પૂર્ણાંક postauth;
	પૂર્ણાંક r;

	debug_f("config len %zu", sshbuf_len(cfg));

	જો ((m = sshbuf_new()) == ખાલી ||
	    (config = sshbuf_new()) == ખાલી ||
	    (opts = sshbuf_new()) == ખાલી ||
	    (confdata = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");

	hostkeys = pack_hostkeys();
	જો ((r = serialise_server_options(&options, &config)) != 0)
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
	જો ((r = sshbuf_put_stringb(m, config)) != 0 ||
	    (r = sshbuf_put_u64(m, options.timing_secret)) != 0 ||
	    (r = sshbuf_put_stringb(m, hostkeys)) != 0 ||
	    (r = sshbuf_put_stringb(m, ssh->kex->server_version)) != 0 ||
	    (r = sshbuf_put_stringb(m, ssh->kex->client_version)) != 0)
		fatal_fr(r, "compose config");

	postauth = (authctxt && authctxt->pw && authctxt->authenticated);
	જો (postauth) {
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

	પાછા (0);
}

#ifdef WITH_OPENSSL
પૂર્ણાંક
mm_answer_moduli(સંરચના ssh *ssh, પૂર્ણાંક sock, સંરચના sshbuf *m)
{
	DH *dh;
	અચલ BIGNUM *dh_p, *dh_g;
	પૂર્ણાંક r;
	u_int min, want, max;

	જો ((r = sshbuf_get_u32(m, &min)) != 0 ||
	    (r = sshbuf_get_u32(m, &want)) != 0 ||
	    (r = sshbuf_get_u32(m, &max)) != 0)
		fatal_fr(r, "parse");

	debug3_f("got parameters: %d %d %d", min, want, max);
	/* We need to check here, too, in case the child got corrupted */
	જો (max < min || want < min || max < want)
		fatal_f("bad parameters: %d %d %d", min, want, max);

	sshbuf_reset(m);

	dh = choose_dh(min, want, max);
	જો (dh == ખાલી) {
		જો ((r = sshbuf_put_u8(m, 0)) != 0)
			fatal_fr(r, "assemble empty");
	} નહીંતર {
		/* Send first bignum */
		DH_get0_pqg(dh, &dh_p, ખાલી, &dh_g);
		જો ((r = sshbuf_put_u8(m, 1)) != 0 ||
		    (r = sshbuf_put_bignum2(m, dh_p)) != 0 ||
		    (r = sshbuf_put_bignum2(m, dh_g)) != 0)
			fatal_fr(r, "assemble");

		DH_free(dh);
	}
	mm_request_send(sock, MONITOR_ANS_MODULI, m);
	પાછા (0);
}
#endif

પૂર્ણાંક
mm_answer_setcompat(સંરચના ssh *ssh, પૂર્ણાંક sock, સંરચના sshbuf *m)
{
	પૂર્ણાંક r;

	debug3_f("entering");

	જો ((r = sshbuf_get_u32(m, &ssh->compat)) != 0)
		fatal_fr(r, "parse");
	compat_set = 1;

	પાછા (0);
}

પૂર્ણાંક
mm_answer_sign(સંરચના ssh *ssh, પૂર્ણાંક sock, સંરચના sshbuf *m)
{
	બાહ્ય પૂર્ણાંક auth_sock;			/* XXX move to state struct? */
	સંરચના sshkey *pubkey, *ચાવી;
	સંરચના sshbuf *sigbuf = ખાલી;
	u_char *p = ખાલી, *signature = ખાલી;
	અક્ષર *alg = ખાલી;
	size_t datlen, siglen;
	પૂર્ણાંક r, is_proof = 0, keyid;
	u_int compat;
	અચલ અક્ષર proof_req[] = "hostkeys-prove-00@openssh.com";
	સ્થિર પૂર્ણાંક nhostkey_proofs_done, *hostkey_proofs_done;

	debug3_f("entering");

	/* Make sure the unpriv process sent the compat bits already */
	જો (!compat_set)
		fatal_f("state error: setcompat never called");

	જો ((r = sshkey_froms(m, &pubkey)) != 0 ||
	    (r = sshbuf_get_string(m, &p, &datlen)) != 0 ||
	    (r = sshbuf_get_cstring(m, &alg, ખાલી)) != 0 ||
	    (r = sshbuf_get_u32(m, &compat)) != 0)
		fatal_fr(r, "parse");

	જો ((keyid = get_hostkey_index(pubkey, 1, ssh)) == -1)
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
	જો (datlen != 20 && datlen != 32 && datlen != 48 && datlen != 64) {
		/*
		 * Construct expected hostkey proof and compare it to what
		 * the client sent us.
		 */
		જો (session_id2_len == 0) /* hostkeys is never first */
			fatal_f("bad data length: %zu", datlen);
		જો ((ચાવી = get_hostkey_public_by_index(keyid, ssh)) == ખાલી)
			fatal_f("no hostkey for index %d", keyid);
		જો (keyid >= nhostkey_proofs_done) {
			hostkey_proofs_done = xrecallocarray(
			    hostkey_proofs_done, nhostkey_proofs_done,
			    keyid + 1, કદ(*hostkey_proofs_done));
			nhostkey_proofs_done = keyid + 1;
		}
		જો (hostkey_proofs_done[keyid]) {
			fatal_f("hostkeys proof requested for %s key %d "
			    "multiple times", sshkey_type(ચાવી), keyid);
		}
		hostkey_proofs_done[keyid] = 1;
		જો ((sigbuf = sshbuf_new()) == ખાલી)
			fatal_f("sshbuf_new");
		જો ((r = sshbuf_put_cstring(sigbuf, proof_req)) != 0 ||
		    (r = sshbuf_put_string(sigbuf, session_id2,
		    session_id2_len)) != 0 ||
		    (r = sshkey_puts(ચાવી, sigbuf)) != 0)
			fatal_fr(r, "assemble private key proof");
		જો (datlen != sshbuf_len(sigbuf) ||
		    memcmp(p, sshbuf_ptr(sigbuf), sshbuf_len(sigbuf)) != 0)
			fatal_f("bad data length: %zu, hostkey proof len %zu",
			    datlen, sshbuf_len(sigbuf));
		sshbuf_free(sigbuf);
		is_proof = 1;
	}

	/* save session id, it will be passed on the first call */
	જો (session_id2_len == 0) {
		session_id2_len = datlen;
		session_id2 = xmalloc(session_id2_len);
		memcpy(session_id2, p, session_id2_len);
	}

	જો ((ચાવી = get_hostkey_by_index(keyid)) != ખાલી) {
		જો ((r = sshkey_sign(ચાવી, &signature, &siglen, p, datlen, alg,
		    options.sk_provider, ખાલી, compat)) != 0)
			fatal_fr(r, "sign");
	} નહીંતર જો ((ચાવી = get_hostkey_public_by_index(keyid, ssh)) != ખાલી &&
	    auth_sock > 0) {
		જો ((r = ssh_agent_sign(auth_sock, ચાવી, &signature, &siglen,
		    p, datlen, alg, compat)) != 0)
			fatal_fr(r, "agent sign");
	} નહીંતર
		fatal_f("no hostkey from index %d", keyid);

	debug3_f("%s %s signature len=%zu", alg,
	    is_proof ? "hostkey proof" : "KEX", siglen);

	sshbuf_reset(m);
	જો ((r = sshbuf_put_string(m, signature, siglen)) != 0)
		fatal_fr(r, "assemble");

	મુક્ત(alg);
	મુક્ત(p);
	મુક્ત(signature);

	mm_request_send(sock, MONITOR_ANS_SIGN, m);

	/* Turn on permissions for getpwnam */
	monitor_permit(mon_dispatch, MONITOR_REQ_PWNAM, 1);

	પાછા (0);
}

#define PUTPW(b, id) \
	કરો { \
		જો ((r = sshbuf_put_string(b, \
		    &pwent->id, કદ(pwent->id))) != 0) \
			fatal_fr(r, "assemble %s", #id); \
	} જ્યારે (0)

શૂન્ય
mm_encode_server_options(સંરચના sshbuf *m)
{
	પૂર્ણાંક r;
	સંરચના sshbuf *config;

	જો ((config = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");
	જો ((r = serialise_server_options(&options, &config)) != 0)
		fatal_fr(r, "serialise_server_options");
	જો ((r = sshbuf_put_stringb(m, config)) != 0)
		fatal_fr(r, "assemble options");
	sshbuf_free(config);
}

/* Retrieves the password entry and also checks if the user is permitted */
પૂર્ણાંક
mm_answer_pwnamallow(સંરચના ssh *ssh, પૂર્ણાંક sock, સંરચના sshbuf *m)
{
	સંરચના passwd *pwent;
	પૂર્ણાંક r, allowed = 0;

	debug3_f("entering");

	/* Make sure the unpriv process sent the compat bits already */
	જો (!compat_set)
		fatal_f("state error: setcompat never called");

	જો (authctxt->attempt++ != 0)
		fatal_f("multiple attempts for getpwnam");

	જો ((r = sshbuf_get_cstring(m, &authctxt->user, ખાલી)) != 0)
		fatal_fr(r, "parse");

	pwent = getpwnamallow(ssh, authctxt->user);

	setproctitle("%s [priv]", pwent ? authctxt->user : "unknown");

	sshbuf_reset(m);

	જો (pwent == ખાલી) {
		invalid_user = 1;
		જો ((r = sshbuf_put_u8(m, 0)) != 0)
			fatal_fr(r, "assemble fakepw");
		authctxt->pw = fakepw();
		જાઓ out;
	}

	allowed = 1;
	authctxt->pw = pwent;
	authctxt->valid = 1;

	/* XXX send fake class/dir/shell, etc. */
	જો ((r = sshbuf_put_u8(m, 1)) != 0)
		fatal_fr(r, "assemble ok");
	PUTPW(m, pw_uid);
	PUTPW(m, pw_gid);
#ifdef HAVE_STRUCT_PASSWD_PW_CHANGE
	PUTPW(m, pw_change);
#endif
#ifdef HAVE_STRUCT_PASSWD_PW_EXPIRE
	PUTPW(m, pw_expire);
#endif
	જો ((r = sshbuf_put_cstring(m, pwent->pw_name)) != 0 ||
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

	જો (options.refuse_connection) {
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
	જો (auth2_setup_methods_lists(authctxt) != 0) {
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
	જો (options.use_pam)
		monitor_permit(mon_dispatch, MONITOR_REQ_PAM_START, 1);
#endif

	પાછા (0);
}

પૂર્ણાંક mm_answer_auth2_read_banner(સંરચના ssh *ssh, પૂર્ણાંક sock, સંરચના sshbuf *m)
{
	અક્ષર *banner;
	પૂર્ણાંક r;

	sshbuf_reset(m);
	banner = auth2_read_banner();
	જો ((r = sshbuf_put_cstring(m, banner != ખાલી ? banner : "")) != 0)
		fatal_fr(r, "assemble");
	mm_request_send(sock, MONITOR_ANS_AUTH2_READ_BANNER, m);
	મુક્ત(banner);

	પાછા (0);
}

પૂર્ણાંક
mm_answer_authserv(સંરચના ssh *ssh, પૂર્ણાંક sock, સંરચના sshbuf *m)
{
	પૂર્ણાંક r;

	monitor_permit_authentications(1);

	જો ((r = sshbuf_get_cstring(m, &authctxt->service, ખાલી)) != 0 ||
	    (r = sshbuf_get_cstring(m, &authctxt->style, ખાલી)) != 0)
		fatal_fr(r, "parse");
	debug3_f("service=%s, style=%s", authctxt->service, authctxt->style);

	જો (strlen(authctxt->style) == 0) {
		મુક્ત(authctxt->style);
		authctxt->style = ખાલી;
	}

	પાછા (0);
}

/*
 * Check that the key type appears in the supplied pattern list, ignoring
 * mismatches in the signature algorithm. (Signature algorithm checks are
 * performed in the unprivileged authentication code).
 * Returns 1 on success, 0 otherwise.
 */
સ્થિર પૂર્ણાંક
ચાવી_base_type_match(અચલ અક્ષર *method, અચલ સંરચના sshkey *ચાવી,
    અચલ અક્ષર *list)
{
	અક્ષર *s, *l, *ol = xstrdup(list);
	પૂર્ણાંક found = 0;

	l = ol;
	માટે ((s = strsep(&l, ",")); s && *s != '\0'; (s = strsep(&l, ","))) {
		જો (sshkey_type_from_name(s) == ચાવી->type) {
			found = 1;
			તોડો;
		}
	}
	જો (!found) {
		error("%s key type %s is not in permitted list %s", method,
		    sshkey_ssh_name(ચાવી), list);
	}

	મુક્ત(ol);
	પાછા found;
}

પૂર્ણાંક
mm_answer_authpassword(સંરચના ssh *ssh, પૂર્ણાંક sock, સંરચના sshbuf *m)
{
	સ્થિર પૂર્ણાંક call_ગણતરી;
	અક્ષર *passwd;
	પૂર્ણાંક r, authenticated;
	size_t plen;

	જો (!options.password_authentication)
		fatal_f("password authentication not enabled");
	જો ((r = sshbuf_get_cstring(m, &passwd, &plen)) != 0)
		fatal_fr(r, "parse");
	/* Only authenticate if the context is valid */
	authenticated = options.password_authentication &&
	    auth_password(ssh, passwd);
	freezero(passwd, plen);

	sshbuf_reset(m);
	જો ((r = sshbuf_put_u32(m, authenticated)) != 0)
		fatal_fr(r, "assemble");
#ifdef USE_PAM
	જો ((r = sshbuf_put_u32(m, sshpam_get_maxtries_reached())) != 0)
		fatal_fr(r, "assemble PAM");
#endif

	debug3_f("sending result %d", authenticated);
	mm_request_send(sock, MONITOR_ANS_AUTHPASSWORD, m);

	call_ગણતરી++;
	જો (plen == 0 && call_ગણતરી == 1)
		auth_method = "none";
	નહીંતર
		auth_method = "password";

	/* Causes monitor loop to terminate if authenticated */
	પાછા (authenticated);
}

#ifdef BSD_AUTH
પૂર્ણાંક
mm_answer_bsdauthquery(સંરચના ssh *ssh, પૂર્ણાંક sock, સંરચના sshbuf *m)
{
	અક્ષર *name, *infotxt;
	u_int numprompts, *echo_on, success;
	અક્ષર **prompts;
	પૂર્ણાંક r;

	જો (!options.kbd_interactive_authentication)
		fatal_f("kbd-int authentication not enabled");
	success = bsdauth_query(authctxt, &name, &infotxt, &numprompts,
	    &prompts, &echo_on) < 0 ? 0 : 1;

	sshbuf_reset(m);
	જો ((r = sshbuf_put_u32(m, success)) != 0)
		fatal_fr(r, "assemble");
	જો (success) {
		જો ((r = sshbuf_put_cstring(m, prompts[0])) != 0)
			fatal_fr(r, "assemble prompt");
	}

	debug3_f("sending challenge success: %u", success);
	mm_request_send(sock, MONITOR_ANS_BSDAUTHQUERY, m);

	જો (success) {
		મુક્ત(name);
		મુક્ત(infotxt);
		મુક્ત(prompts);
		મુક્ત(echo_on);
	}

	પાછા (0);
}

પૂર્ણાંક
mm_answer_bsdauthrespond(સંરચના ssh *ssh, પૂર્ણાંક sock, સંરચના sshbuf *m)
{
	અક્ષર *response;
	પૂર્ણાંક r, authok;

	જો (!options.kbd_interactive_authentication)
		fatal_f("kbd-int authentication not enabled");
	જો (authctxt->as == ખાલી)
		fatal_f("no bsd auth session");

	જો ((r = sshbuf_get_cstring(m, &response, ખાલી)) != 0)
		fatal_fr(r, "parse");
	authok = options.kbd_interactive_authentication &&
	    auth_userresponse(authctxt->as, response, 0);
	authctxt->as = ખાલી;
	debug3_f("<%s> = <%d>", response, authok);
	મુક્ત(response);

	sshbuf_reset(m);
	જો ((r = sshbuf_put_u32(m, authok)) != 0)
		fatal_fr(r, "assemble");

	debug3_f("sending authenticated: %d", authok);
	mm_request_send(sock, MONITOR_ANS_BSDAUTHRESPOND, m);

	auth_method = "keyboard-interactive";
	auth_submethod = "bsdauth";

	પાછા (authok != 0);
}
#endif

#ifdef USE_PAM
પૂર્ણાંક
mm_answer_pam_start(સંરચના ssh *ssh, પૂર્ણાંક sock, સંરચના sshbuf *m)
{
	જો (!options.use_pam)
		fatal_f("UsePAM not set, but ended up in %s anyway", __func__);

	start_pam(ssh);

	monitor_permit(mon_dispatch, MONITOR_REQ_PAM_ACCOUNT, 1);
	જો (options.kbd_interactive_authentication)
		monitor_permit(mon_dispatch, MONITOR_REQ_PAM_INIT_CTX, 1);

	પાછા (0);
}

પૂર્ણાંક
mm_answer_pam_account(સંરચના ssh *ssh, પૂર્ણાંક sock, સંરચના sshbuf *m)
{
	u_int ret;
	પૂર્ણાંક r;

	જો (!options.use_pam)
		fatal_f("PAM not enabled");

	ret = do_pam_account();

	જો ((r = sshbuf_put_u32(m, ret)) != 0 ||
	    (r = sshbuf_put_stringb(m, loginmsg)) != 0)
		fatal_fr(r, "buffer error");
	sshbuf_reset(loginmsg);

	mm_request_send(sock, MONITOR_ANS_PAM_ACCOUNT, m);

	પાછા (ret);
}

સ્થિર શૂન્ય *sshpam_ctxt, *sshpam_authok;
બાહ્ય KbdintDevice sshpam_device;

પૂર્ણાંક
mm_answer_pam_init_ctx(સંરચના ssh *ssh, પૂર્ણાંક sock, સંરચના sshbuf *m)
{
	u_int ok = 0;
	પૂર્ણાંક r;

	debug3_f("entering");
	જો (!options.kbd_interactive_authentication)
		fatal_f("kbd-int authentication not enabled");
	જો (sshpam_ctxt != ખાલી)
		fatal_f("already called");
	sshpam_ctxt = (sshpam_device.init_ctx)(authctxt);
	sshpam_authok = ખાલી;
	sshbuf_reset(m);
	જો (sshpam_ctxt != ખાલી) {
		monitor_permit(mon_dispatch, MONITOR_REQ_PAM_FREE_CTX, 1);
		monitor_permit(mon_dispatch, MONITOR_REQ_PAM_QUERY, 1);
		ok = 1;
	}
	જો ((r = sshbuf_put_u32(m, ok)) != 0)
		fatal_fr(r, "buffer error");
	mm_request_send(sock, MONITOR_ANS_PAM_INIT_CTX, m);
	પાછા (0);
}

પૂર્ણાંક
mm_answer_pam_query(સંરચના ssh *ssh, પૂર્ણાંક sock, સંરચના sshbuf *m)
{
	અક્ષર *name = ખાલી, *info = ખાલી, **prompts = ખાલી;
	u_int i, અંક = 0, *echo_on = 0;
	પૂર્ણાંક r, ret;

	debug3_f("entering");
	sshpam_authok = ખાલી;
	જો (sshpam_ctxt == ખાલી)
		fatal_f("no context");
	ret = (sshpam_device.query)(sshpam_ctxt, &name, &info,
	    &અંક, &prompts, &echo_on);
	જો (ret == 0 && અંક == 0 && sshpam_priv_kbdint_authdone(sshpam_ctxt))
		sshpam_authok = sshpam_ctxt;
	જો (અંક > 1 || name == ખાલી || info == ખાલી)
		fatal("sshpam_device.query failed");
	monitor_permit(mon_dispatch, MONITOR_REQ_PAM_RESPOND, 1);
	sshbuf_reset(m);
	જો ((r = sshbuf_put_u32(m, ret)) != 0 ||
	    (r = sshbuf_put_cstring(m, name)) != 0 ||
	    (r = sshbuf_put_cstring(m, info)) != 0 ||
	    (r = sshbuf_put_u32(m, sshpam_get_maxtries_reached())) != 0 ||
	    (r = sshbuf_put_u32(m, અંક)) != 0)
		fatal_fr(r, "buffer error");
	મુક્ત(name);
	મુક્ત(info);
	માટે (i = 0; i < અંક; ++i) {
		જો ((r = sshbuf_put_cstring(m, prompts[i])) != 0 ||
		    (r = sshbuf_put_u32(m, echo_on[i])) != 0)
			fatal_fr(r, "buffer error");
		મુક્ત(prompts[i]);
	}
	મુક્ત(prompts);
	મુક્ત(echo_on);
	auth_method = "keyboard-interactive";
	auth_submethod = "pam";
	mm_request_send(sock, MONITOR_ANS_PAM_QUERY, m);
	પાછા (0);
}

પૂર્ણાંક
mm_answer_pam_respond(સંરચના ssh *ssh, પૂર્ણાંક sock, સંરચના sshbuf *m)
{
	અક્ષર **resp;
	u_int i, અંક;
	પૂર્ણાંક r, ret;

	debug3_f("entering");
	જો (sshpam_ctxt == ખાલી)
		fatal_f("no context");
	sshpam_authok = ખાલી;
	જો ((r = sshbuf_get_u32(m, &અંક)) != 0)
		fatal_fr(r, "buffer error");
	જો (અંક > PAM_MAX_અંક_સંદેશ) {
		fatal_f("Too many PAM messages, got %u, expected <= %u",
		    અંક, (unsigned)PAM_MAX_અંક_સંદેશ);
	}
	જો (અંક > 0) {
		resp = xcalloc(અંક, કદ(અક્ષર *));
		માટે (i = 0; i < અંક; ++i) {
			જો ((r = sshbuf_get_cstring(m, &(resp[i]), ખાલી)) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
		}
		ret = (sshpam_device.respond)(sshpam_ctxt, અંક, resp);
		માટે (i = 0; i < અંક; ++i)
			મુક્ત(resp[i]);
		મુક્ત(resp);
	} નહીંતર {
		ret = (sshpam_device.respond)(sshpam_ctxt, અંક, ખાલી);
	}
	sshbuf_reset(m);
	જો ((r = sshbuf_put_u32(m, ret)) != 0)
		fatal_fr(r, "buffer error");
	mm_request_send(sock, MONITOR_ANS_PAM_RESPOND, m);
	auth_method = "keyboard-interactive";
	auth_submethod = "pam";
	જો (ret == 0)
		sshpam_authok = sshpam_ctxt;
	પાછા (0);
}

પૂર્ણાંક
mm_answer_pam_free_ctx(સંરચના ssh *ssh, પૂર્ણાંક sock, સંરચના sshbuf *m)
{
	પૂર્ણાંક r = sshpam_authok != ખાલી && sshpam_authok == sshpam_ctxt;

	debug3_f("entering");
	જો (sshpam_ctxt == ખાલી)
		fatal_f("no context");
	(sshpam_device.free_ctx)(sshpam_ctxt);
	sshpam_ctxt = sshpam_authok = ખાલી;
	sshbuf_reset(m);
	mm_request_send(sock, MONITOR_ANS_PAM_FREE_CTX, m);
	/* Allow another attempt */
	monitor_permit(mon_dispatch, MONITOR_REQ_PAM_INIT_CTX, 1);
	auth_method = "keyboard-interactive";
	auth_submethod = "pam";
	પાછા r;
}
#endif

પૂર્ણાંક
mm_answer_keyallowed(સંરચના ssh *ssh, પૂર્ણાંક sock, સંરચના sshbuf *m)
{
	સંરચના sshkey *ચાવી = ખાલી;
	અક્ષર *cuser, *chost;
	u_int pubkey_auth_attempt;
	u_int type = 0;
	પૂર્ણાંક r, allowed = 0;
	સંરચના sshauthopt *opts = ખાલી;

	debug3_f("entering");
	જો ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_cstring(m, &cuser, ખાલી)) != 0 ||
	    (r = sshbuf_get_cstring(m, &chost, ખાલી)) != 0 ||
	    (r = sshkey_froms(m, &ચાવી)) != 0 ||
	    (r = sshbuf_get_u32(m, &pubkey_auth_attempt)) != 0)
		fatal_fr(r, "parse");

	જો (ચાવી != ખાલી && authctxt->valid) {
		પસંદગી (type) {
		સ્થિતિ MM_USERKEY:
			auth_method = "publickey";
			જો (!options.pubkey_authentication)
				તોડો;
			જો (auth2_ચાવી_already_used(authctxt, ચાવી))
				તોડો;
			જો (!ચાવી_base_type_match(auth_method, ચાવી,
			    options.pubkey_accepted_algos))
				તોડો;
			allowed = user_ચાવી_allowed(ssh, authctxt->pw, ચાવી,
			    pubkey_auth_attempt, &opts);
			તોડો;
		સ્થિતિ MM_HOSTKEY:
			auth_method = "hostbased";
			જો (!options.hostbased_authentication)
				તોડો;
			જો (auth2_ચાવી_already_used(authctxt, ચાવી))
				તોડો;
			જો (!ચાવી_base_type_match(auth_method, ચાવી,
			    options.hostbased_accepted_algos))
				તોડો;
			allowed = hostbased_ચાવી_allowed(ssh, authctxt->pw,
			    cuser, chost, ચાવી);
			auth2_record_info(authctxt,
			    "client user \"%.100s\", client host \"%.100s\"",
			    cuser, chost);
			તોડો;
		મૂળભૂત:
			fatal_f("unknown key type %u", type);
			તોડો;
		}
	}

	debug3_f("%s authentication%s: %s key is %s", auth_method,
	    pubkey_auth_attempt ? "" : " test",
	    (ચાવી == ખાલી || !authctxt->valid) ? "invalid" : sshkey_type(ચાવી),
	    allowed ? "allowed" : "not allowed");

	auth2_record_ચાવી(authctxt, 0, ચાવી);

	/* clear temporarily storage (used by verify) */
	monitor_reset_ચાવી_state();

	જો (allowed) {
		/* Save temporarily for comparison in verify */
		જો ((r = sshkey_to_blob(ચાવી, &ચાવી_blob, &ચાવી_bloblen)) != 0)
			fatal_fr(r, "sshkey_to_blob");
		ચાવી_blobtype = type;
		ચાવી_opts = opts;
		hostbased_cuser = cuser;
		hostbased_chost = chost;
	} નહીંતર {
		/* Log failed attempt */
		auth_log(ssh, 0, 0, auth_method, ખાલી);
		મુક્ત(cuser);
		મુક્ત(chost);
	}
	sshkey_free(ચાવી);

	sshbuf_reset(m);
	જો ((r = sshbuf_put_u32(m, allowed)) != 0)
		fatal_fr(r, "assemble");
	જો (opts != ખાલી && (r = sshauthopt_serialise(opts, m, 1)) != 0)
		fatal_fr(r, "sshauthopt_serialise");
	mm_request_send(sock, MONITOR_ANS_KEYALLOWED, m);

	જો (!allowed)
		sshauthopt_free(opts);

	પાછા (0);
}

સ્થિર પૂર્ણાંક
monitor_valid_userblob(સંરચના ssh *ssh, અચલ u_char *data, u_int datalen)
{
	સંરચના sshbuf *b;
	સંરચના sshkey *hostkey = ખાલી;
	અચલ u_char *p;
	અક્ષર *userstyle, *cp;
	size_t len;
	u_char type;
	પૂર્ણાંક hostbound = 0, r, fail = 0;

	જો ((b = sshbuf_from(data, datalen)) == ખાલી)
		fatal_f("sshbuf_from");

	જો ((r = sshbuf_get_string_direct(b, &p, &len)) != 0)
		fatal_fr(r, "parse sessionid");
	જો ((session_id2 == ખાલી) ||
	    (len != session_id2_len) ||
	    (timingsafe_bcmp(p, session_id2, session_id2_len) != 0))
		fail++;
	જો ((r = sshbuf_get_u8(b, &type)) != 0)
		fatal_fr(r, "parse type");
	જો (type != SSH2_સંદેશ_USERAUTH_REQUEST)
		fail++;
	જો ((r = sshbuf_get_cstring(b, &cp, ખાલી)) != 0)
		fatal_fr(r, "parse userstyle");
	xasprintf(&userstyle, "%s%s%s", authctxt->user,
	    authctxt->style ? ":" : "",
	    authctxt->style ? authctxt->style : "");
	જો (strcmp(userstyle, cp) != 0) {
		logit("wrong user name passed to monitor: "
		    "expected %s != %.100s", userstyle, cp);
		fail++;
	}
	મુક્ત(userstyle);
	મુક્ત(cp);
	જો ((r = sshbuf_skip_string(b)) != 0 ||	/* service */
	    (r = sshbuf_get_cstring(b, &cp, ખાલી)) != 0)
		fatal_fr(r, "parse method");
	જો (strcmp("publickey", cp) != 0) {
		જો (strcmp("publickey-hostbound-v00@openssh.com", cp) == 0)
			hostbound = 1;
		નહીંતર
			fail++;
	}
	મુક્ત(cp);
	જો ((r = sshbuf_get_u8(b, &type)) != 0)
		fatal_fr(r, "parse pktype");
	જો (type == 0)
		fail++;
	જો ((r = sshbuf_skip_string(b)) != 0 ||	/* pkalg */
	    (r = sshbuf_skip_string(b)) != 0 ||	/* pkblob */
	    (hostbound && (r = sshkey_froms(b, &hostkey)) != 0))
		fatal_fr(r, "parse pk");
	જો (sshbuf_len(b) != 0)
		fail++;
	sshbuf_free(b);
	જો (hostkey != ખાલી) {
		/*
		 * Ensure this is actually one of our hostkeys; unfortunately
		 * can't check ssh->kex->initial_hostkey directly at this point
		 * as packet state has not yet been exported to monitor.
		 */
		જો (get_hostkey_index(hostkey, 1, ssh) == -1)
			fatal_f("hostbound hostkey does not match");
		sshkey_free(hostkey);
	}
	પાછા (fail == 0);
}

સ્થિર પૂર્ણાંક
monitor_valid_hostbasedblob(અચલ u_char *data, u_int datalen,
    અચલ અક્ષર *cuser, અચલ અક્ષર *chost)
{
	સંરચના sshbuf *b;
	અચલ u_char *p;
	અક્ષર *cp, *userstyle;
	size_t len;
	પૂર્ણાંક r, fail = 0;
	u_char type;

	જો ((b = sshbuf_from(data, datalen)) == ખાલી)
		fatal_f("sshbuf_new");
	જો ((r = sshbuf_get_string_direct(b, &p, &len)) != 0)
		fatal_fr(r, "parse sessionid");

	જો ((session_id2 == ખાલી) ||
	    (len != session_id2_len) ||
	    (timingsafe_bcmp(p, session_id2, session_id2_len) != 0))
		fail++;

	જો ((r = sshbuf_get_u8(b, &type)) != 0)
		fatal_fr(r, "parse type");
	જો (type != SSH2_સંદેશ_USERAUTH_REQUEST)
		fail++;
	જો ((r = sshbuf_get_cstring(b, &cp, ખાલી)) != 0)
		fatal_fr(r, "parse userstyle");
	xasprintf(&userstyle, "%s%s%s", authctxt->user,
	    authctxt->style ? ":" : "",
	    authctxt->style ? authctxt->style : "");
	જો (strcmp(userstyle, cp) != 0) {
		logit("wrong user name passed to monitor: "
		    "expected %s != %.100s", userstyle, cp);
		fail++;
	}
	મુક્ત(userstyle);
	મુક્ત(cp);
	જો ((r = sshbuf_skip_string(b)) != 0 ||	/* service */
	    (r = sshbuf_get_cstring(b, &cp, ખાલી)) != 0)
		fatal_fr(r, "parse method");
	જો (strcmp(cp, "hostbased") != 0)
		fail++;
	મુક્ત(cp);
	જો ((r = sshbuf_skip_string(b)) != 0 ||	/* pkalg */
	    (r = sshbuf_skip_string(b)) != 0)	/* pkblob */
		fatal_fr(r, "parse pk");

	/* verify client host, strip trailing dot if necessary */
	જો ((r = sshbuf_get_cstring(b, &cp, ખાલી)) != 0)
		fatal_fr(r, "parse host");
	જો (((len = strlen(cp)) > 0) && cp[len - 1] == '.')
		cp[len - 1] = '\0';
	જો (strcmp(cp, chost) != 0)
		fail++;
	મુક્ત(cp);

	/* verify client user */
	જો ((r = sshbuf_get_cstring(b, &cp, ખાલી)) != 0)
		fatal_fr(r, "parse ruser");
	જો (strcmp(cp, cuser) != 0)
		fail++;
	મુક્ત(cp);

	જો (sshbuf_len(b) != 0)
		fail++;
	sshbuf_free(b);
	પાછા (fail == 0);
}

પૂર્ણાંક
mm_answer_keyverify(સંરચના ssh *ssh, પૂર્ણાંક sock, સંરચના sshbuf *m)
{
	સંરચના sshkey *ચાવી;
	અચલ u_char *signature, *data, *blob;
	અક્ષર *sigalg = ખાલી, *fp = ખાલી;
	size_t signaturelen, datalen, bloblen;
	પૂર્ણાંક r, ret, req_presence = 0, req_verify = 0, valid_data = 0;
	પૂર્ણાંક encoded_ret;
	સંરચના sshkey_sig_details *sig_details = ખાલી;

	જો ((r = sshbuf_get_string_direct(m, &blob, &bloblen)) != 0 ||
	    (r = sshbuf_get_string_direct(m, &signature, &signaturelen)) != 0 ||
	    (r = sshbuf_get_string_direct(m, &data, &datalen)) != 0 ||
	    (r = sshbuf_get_cstring(m, &sigalg, ખાલી)) != 0)
		fatal_fr(r, "parse");

	જો (hostbased_cuser == ખાલી || hostbased_chost == ખાલી ||
	  !monitor_allowed_ચાવી(blob, bloblen))
		fatal_f("bad key, not previously allowed");

	/* Empty signature algorithm means NULL. */
	જો (*sigalg == '\0') {
		મુક્ત(sigalg);
		sigalg = ખાલી;
	}

	/* XXX use sshkey_froms here; need to change key_blob, etc. */
	જો ((r = sshkey_from_blob(blob, bloblen, &ચાવી)) != 0)
		fatal_fr(r, "parse key");

	પસંદગી (ચાવી_blobtype) {
	સ્થિતિ MM_USERKEY:
		valid_data = monitor_valid_userblob(ssh, data, datalen);
		auth_method = "publickey";
		તોડો;
	સ્થિતિ MM_HOSTKEY:
		valid_data = monitor_valid_hostbasedblob(data, datalen,
		    hostbased_cuser, hostbased_chost);
		auth_method = "hostbased";
		તોડો;
	મૂળભૂત:
		valid_data = 0;
		તોડો;
	}
	જો (!valid_data)
		fatal_f("bad %s signature data blob",
		    ચાવી_blobtype == MM_USERKEY ? "userkey" :
		    (ચાવી_blobtype == MM_HOSTKEY ? "hostkey" : "unknown"));

	જો ((fp = sshkey_fingerprint(ચાવી, options.fingerprint_hash,
	    SSH_FP_DEFAULT)) == ખાલી)
		fatal_f("sshkey_fingerprint failed");

	ret = sshkey_verify(ચાવી, signature, signaturelen, data, datalen,
	    sigalg, ssh->compat, &sig_details);
	debug3_f("%s %s signature using %s %s%s%s", auth_method,
	    sshkey_type(ચાવી), sigalg == ખાલી ? "default" : sigalg,
	    (ret == 0) ? "verified" : "unverified",
	    (ret != 0) ? ": " : "", (ret != 0) ? ssh_err(ret) : "");

	જો (ret == 0 && ચાવી_blobtype == MM_USERKEY && sig_details != ખાલી) {
		req_presence = (options.pubkey_auth_options &
		    PUBKEYAUTH_TOUCH_REQUIRED) ||
		    !ચાવી_opts->no_require_user_presence;
		જો (req_presence &&
		    (sig_details->sk_flags & SSH_SK_USER_PRESENCE_REQD) == 0) {
			error("public key %s %s signature for %s%s from %.128s "
			    "port %d rejected: user presence "
			    "(authenticator touch) requirement not met ",
			    sshkey_type(ચાવી), fp,
			    authctxt->valid ? "" : "invalid user ",
			    authctxt->user, ssh_remote_ipaddr(ssh),
			    ssh_remote_port(ssh));
			ret = SSH_ERR_SIGNATURE_INVALID;
		}
		req_verify = (options.pubkey_auth_options &
		    PUBKEYAUTH_VERIFY_REQUIRED) || ચાવી_opts->require_verify;
		જો (req_verify &&
		    (sig_details->sk_flags & SSH_SK_USER_VERIFICATION_REQD) == 0) {
			error("public key %s %s signature for %s%s from %.128s "
			    "port %d rejected: user verification requirement "
			    "not met ", sshkey_type(ચાવી), fp,
			    authctxt->valid ? "" : "invalid user ",
			    authctxt->user, ssh_remote_ipaddr(ssh),
			    ssh_remote_port(ssh));
			ret = SSH_ERR_SIGNATURE_INVALID;
		}
	}
	auth2_record_ચાવી(authctxt, ret == 0, ચાવી);

	જો (ચાવી_blobtype == MM_USERKEY && ret == 0)
		auth_activate_options(ssh, ચાવી_opts);
	monitor_reset_ચાવી_state();

	sshbuf_reset(m);

	/* encode ret != 0 as positive integer, since we're sending u32 */
	encoded_ret = (ret != 0);
	જો ((r = sshbuf_put_u32(m, encoded_ret)) != 0 ||
	    (r = sshbuf_put_u8(m, sig_details != ખાલી)) != 0)
		fatal_fr(r, "assemble");
	જો (sig_details != ખાલી) {
		જો ((r = sshbuf_put_u32(m, sig_details->sk_counter)) != 0 ||
		    (r = sshbuf_put_u8(m, sig_details->sk_flags)) != 0)
			fatal_fr(r, "assemble sk");
	}
	sshkey_sig_details_free(sig_details);
	mm_request_send(sock, MONITOR_ANS_KEYVERIFY, m);

	મુક્ત(sigalg);
	મુક્ત(fp);
	sshkey_free(ચાવી);

	પાછા ret == 0;
}

સ્થિર શૂન્ય
mm_record_login(સંરચના ssh *ssh, Session *s, સંરચના passwd *pw)
{
	socklen_t fromlen;
	સંરચના sockaddr_storage from;

	/*
	 * Get IP address of client. If the connection is not a socket, let
	 * the address be 0.0.0.0.
	 */
	memset(&from, 0, કદ(from));
	fromlen = કદ(from);
	જો (ssh_packet_connection_is_on_socket(ssh)) {
		જો (getpeername(ssh_packet_get_connection_in(ssh),
		    (સંરચના sockaddr *)&from, &fromlen) == -1) {
			debug("getpeername: %.100s", strerror(errno));
			cleanup_exit(255);
		}
	}
	/* Record that there was a login on that tty from the remote host. */
	record_login(s->pid, s->tty, pw->pw_name, pw->pw_uid,
	    session_get_remote_name_or_ip(ssh, utmp_len, options.use_dns),
	    (સંરચના sockaddr *)&from, fromlen);
}

સ્થિર શૂન્ય
mm_session_close(Session *s)
{
	debug3_f("session %d pid %ld", s->self, (long)s->pid);
	જો (s->ttyfd != -1) {
		debug3_f("tty %s ptyfd %d", s->tty, s->ptyfd);
		session_pty_cleanup2(s);
	}
	session_unused(s->self);
}

પૂર્ણાંક
mm_answer_pty(સંરચના ssh *ssh, પૂર્ણાંક sock, સંરચના sshbuf *m)
{
	બાહ્ય સંરચના monitor *pmonitor;
	Session *s;
	પૂર્ણાંક r, res, fd0;

	debug3_f("entering");

	sshbuf_reset(m);
	s = session_new();
	જો (s == ખાલી)
		જાઓ error;
	s->authctxt = authctxt;
	s->pw = authctxt->pw;
	s->pid = pmonitor->m_pid;
	res = pty_allocate(&s->ptyfd, &s->ttyfd, s->tty, કદ(s->tty));
	જો (res == 0)
		જાઓ error;
	pty_setowner(authctxt->pw, s->tty);

	જો ((r = sshbuf_put_u32(m, 1)) != 0 ||
	    (r = sshbuf_put_cstring(m, s->tty)) != 0)
		fatal_fr(r, "assemble");

	/* We need to trick ttyslot */
	જો (dup2(s->ttyfd, 0) == -1)
		fatal_f("dup2");

	mm_record_login(ssh, s, authctxt->pw);

	/* Now we can close the file descriptor again */
	close(0);

	/* send messages generated by record_login */
	જો ((r = sshbuf_put_stringb(m, loginmsg)) != 0)
		fatal_fr(r, "assemble loginmsg");
	sshbuf_reset(loginmsg);

	mm_request_send(sock, MONITOR_ANS_PTY, m);

	જો (mm_send_fd(sock, s->ptyfd) == -1 ||
	    mm_send_fd(sock, s->ttyfd) == -1)
		fatal_f("send fds failed");

	/* make sure nothing uses fd 0 */
	જો ((fd0 = open(_PATH_DEVNULL, O_RDONLY)) == -1)
		fatal_f("open(/dev/null): %s", strerror(errno));
	જો (fd0 != 0)
		error_f("fd0 %d != 0", fd0);

	/* slave side of pty is not needed */
	close(s->ttyfd);
	s->ttyfd = s->ptyfd;
	/* no need to dup() because nobody closes ptyfd */
	s->ptymaster = s->ptyfd;

	debug3_f("tty %s ptyfd %d", s->tty, s->ttyfd);

	પાછા (0);

 error:
	જો (s != ખાલી)
		mm_session_close(s);
	જો ((r = sshbuf_put_u32(m, 0)) != 0)
		fatal_fr(r, "assemble 0");
	mm_request_send(sock, MONITOR_ANS_PTY, m);
	પાછા (0);
}

પૂર્ણાંક
mm_answer_pty_cleanup(સંરચના ssh *ssh, પૂર્ણાંક sock, સંરચના sshbuf *m)
{
	Session *s;
	અક્ષર *tty;
	પૂર્ણાંક r;

	debug3_f("entering");

	જો ((r = sshbuf_get_cstring(m, &tty, ખાલી)) != 0)
		fatal_fr(r, "parse tty");
	જો ((s = session_by_tty(tty)) != ખાલી)
		mm_session_close(s);
	sshbuf_reset(m);
	મુક્ત(tty);
	પાછા (0);
}

પૂર્ણાંક
mm_answer_term(સંરચના ssh *ssh, પૂર્ણાંક sock, સંરચના sshbuf *req)
{
	બાહ્ય સંરચના monitor *pmonitor;
	પૂર્ણાંક res, status;

	debug3_f("tearing down sessions");

	/* The child is terminating */
	session_destroy_all(ssh, &mm_session_close);

#ifdef USE_PAM
	જો (options.use_pam)
		sshpam_cleanup();
#endif

	જ્યારે (waitpid(pmonitor->m_pid, &status, 0) == -1)
		જો (errno != EINTR)
			exit(1);

	res = WIFEXITED(status) ? WEXITSTATUS(status) : 1;

	/* Terminate process */
	exit(res);
}

#ifdef SSH_AUDIT_EVENTS
/* Report that an audit event occurred */
પૂર્ણાંક
mm_answer_audit_event(સંરચના ssh *ssh, પૂર્ણાંક socket, સંરચના sshbuf *m)
{
	u_int n;
	ssh_audit_event_t event;
	પૂર્ણાંક r;

	debug3_f("entering");

	જો ((r = sshbuf_get_u32(m, &n)) != 0)
		fatal_fr(r, "buffer error");
	event = (ssh_audit_event_t)n;
	પસંદગી (event) {
	સ્થિતિ SSH_AUTH_FAIL_PUBKEY:
	સ્થિતિ SSH_AUTH_FAIL_HOSTBASED:
	સ્થિતિ SSH_AUTH_FAIL_GSSAPI:
	સ્થિતિ SSH_LOGIN_EXCEED_MAXTRIES:
	સ્થિતિ SSH_LOGIN_મૂળ_DENIED:
	સ્થિતિ SSH_CONNECTION_CLOSE:
	સ્થિતિ SSH_INVALID_USER:
		audit_event(ssh, event);
		તોડો;
	મૂળભૂત:
		fatal("Audit event type %d not permitted", event);
	}

	પાછા (0);
}

પૂર્ણાંક
mm_answer_audit_command(સંરચના ssh *ssh, પૂર્ણાંક socket, સંરચના sshbuf *m)
{
	અક્ષર *cmd;
	પૂર્ણાંક r;

	debug3_f("entering");
	જો ((r = sshbuf_get_cstring(m, &cmd, ખાલી)) != 0)
		fatal_fr(r, "buffer error");
	/* sanity check command, if so how? */
	audit_run_command(cmd);
	મુક્ત(cmd);
	પાછા (0);
}
#endif /* SSH_AUDIT_EVENTS */

શૂન્ય
monitor_clear_keystate(સંરચના ssh *ssh, સંરચના monitor *pmonitor)
{
	ssh_clear_newkeys(ssh, MODE_IN);
	ssh_clear_newkeys(ssh, MODE_OUT);
	sshbuf_free(child_state);
	child_state = ખાલી;
}

શૂન્ય
monitor_apply_keystate(સંરચના ssh *ssh, સંરચના monitor *pmonitor)
{
	સંરચના kex *kex;
	પૂર્ણાંક r;

	debug3_f("packet_set_state");
	જો ((r = ssh_packet_set_state(ssh, child_state)) != 0)
		fatal_fr(r, "packet_set_state");
	sshbuf_free(child_state);
	child_state = ખાલી;
	જો ((kex = ssh->kex) == ખાલી)
		fatal_f("internal error: ssh->kex == NULL");
	જો (session_id2_len != sshbuf_len(ssh->kex->session_id)) {
		fatal_f("incorrect session id length %zu (expected %u)",
		    sshbuf_len(ssh->kex->session_id), session_id2_len);
	}
	જો (memcmp(sshbuf_ptr(ssh->kex->session_id), session_id2,
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
	kex->load_host_public_ચાવી=&get_hostkey_public_by_type;
	kex->load_host_private_ચાવી=&get_hostkey_private_by_type;
	kex->host_ચાવી_index=&get_hostkey_index;
	kex->sign = sshd_hostkey_sign;
}

/* This function requires careful sanity checking */

શૂન્ય
mm_get_keystate(સંરચના ssh *ssh, સંરચના monitor *pmonitor)
{
	debug3_f("Waiting for new keys");

	જો ((child_state = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");
	mm_request_receive_expect(pmonitor->m_sendfd, MONITOR_REQ_KEYEXPORT,
	    child_state);
	debug3_f("GOT new keys");
}


/* XXX */

સ્થિર શૂન્ય
monitor_openfds(સંરચના monitor *mon, પૂર્ણાંક do_logfds)
{
	પૂર્ણાંક pair[2];
#ifdef SO_ZEROIZE
	પૂર્ણાંક on = 1;
#endif

	જો (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == -1)
		fatal_f("socketpair: %s", strerror(errno));
#ifdef SO_ZEROIZE
	જો (setsockopt(pair[0], SOL_SOCKET, SO_ZEROIZE, &on, કદ(on)) == -1)
		error("setsockopt SO_ZEROIZE(0): %.100s", strerror(errno));
	જો (setsockopt(pair[1], SOL_SOCKET, SO_ZEROIZE, &on, કદ(on)) == -1)
		error("setsockopt SO_ZEROIZE(1): %.100s", strerror(errno));
#endif
	FD_CLOSEONEXEC(pair[0]);
	FD_CLOSEONEXEC(pair[1]);
	mon->m_recvfd = pair[0];
	mon->m_sendfd = pair[1];

	જો (do_logfds) {
		જો (pipe(pair) == -1)
			fatal_f("pipe: %s", strerror(errno));
		FD_CLOSEONEXEC(pair[0]);
		FD_CLOSEONEXEC(pair[1]);
		mon->m_log_recvfd = pair[0];
		mon->m_log_sendfd = pair[1];
	} નહીંતર
		mon->m_log_recvfd = mon->m_log_sendfd = -1;
}

સંરચના monitor *
monitor_init(શૂન્ય)
{
	સંરચના monitor *mon;

	mon = xcalloc(1, કદ(*mon));
	monitor_openfds(mon, 1);

	પાછા mon;
}

શૂન્ય
monitor_reinit(સંરચના monitor *mon)
{
	monitor_openfds(mon, 0);
}

પૂર્ણાંક
monitor_auth_attempted(શૂન્ય)
{
	પાછા auth_attempted;
}

પૂર્ણાંક
monitor_invalid_user(શૂન્ય)
{
	પાછા invalid_user;
}

#ifdef GSSAPI
પૂર્ણાંક
mm_answer_gss_setup_ctx(સંરચના ssh *ssh, પૂર્ણાંક sock, સંરચના sshbuf *m)
{
	gss_OID_desc goid;
	OM_uint32 major;
	size_t len;
	u_char *p;
	પૂર્ણાંક r;

	જો (!options.gss_authentication)
		fatal_f("GSSAPI authentication not enabled");

	ssh_gssapi_cleanup_global_client();

	જો ((r = sshbuf_get_string(m, &p, &len)) != 0)
		fatal_fr(r, "parse");
	goid.elements = p;
	goid.length = len;

	major = ssh_gssapi_server_ctx(&gsscontext, &goid);

	મુક્ત(goid.elements);

	sshbuf_reset(m);
	જો ((r = sshbuf_put_u32(m, major)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(sock, MONITOR_ANS_GSSSETUP, m);

	/* Now we have a context, enable the step */
	monitor_permit(mon_dispatch, MONITOR_REQ_GSSSTEP, 1);

	પાછા (0);
}

પૂર્ણાંક
mm_answer_gss_accept_ctx(સંરચના ssh *ssh, પૂર્ણાંક sock, સંરચના sshbuf *m)
{
	gss_buffer_desc in;
	gss_buffer_desc out = GSS_C_EMPTY_BUFFER;
	OM_uint32 major, minor;
	OM_uint32 flags = 0; /* GSI needs this */
	પૂર્ણાંક r;

	જો (!options.gss_authentication)
		fatal_f("GSSAPI authentication not enabled");

	જો ((r = ssh_gssapi_get_buffer_desc(m, &in)) != 0)
		fatal_fr(r, "ssh_gssapi_get_buffer_desc");
	major = ssh_gssapi_accept_ctx(gsscontext, &in, &out, &flags);
	મુક્ત(in.કિંમત);

	sshbuf_reset(m);
	જો ((r = sshbuf_put_u32(m, major)) != 0 ||
	    (r = sshbuf_put_string(m, out.કિંમત, out.length)) != 0 ||
	    (r = sshbuf_put_u32(m, flags)) != 0)
		fatal_fr(r, "assemble");
	mm_request_send(sock, MONITOR_ANS_GSSSTEP, m);

	gss_release_buffer(&minor, &out);

	જો (major == GSS_S_COMPLETE) {
		monitor_permit(mon_dispatch, MONITOR_REQ_GSSSTEP, 0);
		monitor_permit(mon_dispatch, MONITOR_REQ_GSSUSEROK, 1);
		monitor_permit(mon_dispatch, MONITOR_REQ_GSSCHECKMIC, 1);
	}
	પાછા (0);
}

પૂર્ણાંક
mm_answer_gss_checkmic(સંરચના ssh *ssh, પૂર્ણાંક sock, સંરચના sshbuf *m)
{
	gss_buffer_desc gssbuf, mic;
	OM_uint32 ret;
	પૂર્ણાંક r;

	જો (!options.gss_authentication)
		fatal_f("GSSAPI authentication not enabled");

	જો ((r = ssh_gssapi_get_buffer_desc(m, &gssbuf)) != 0 ||
	    (r = ssh_gssapi_get_buffer_desc(m, &mic)) != 0)
		fatal_fr(r, "ssh_gssapi_get_buffer_desc");

	ret = ssh_gssapi_checkmic(gsscontext, &gssbuf, &mic);

	મુક્ત(gssbuf.કિંમત);
	મુક્ત(mic.કિંમત);

	sshbuf_reset(m);
	જો ((r = sshbuf_put_u32(m, ret)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(sock, MONITOR_ANS_GSSCHECKMIC, m);

	જો (!GSS_ERROR(ret))
		monitor_permit(mon_dispatch, MONITOR_REQ_GSSUSEROK, 1);

	પાછા (0);
}

પૂર્ણાંક
mm_answer_gss_userok(સંરચના ssh *ssh, પૂર્ણાંક sock, સંરચના sshbuf *m)
{
	પૂર્ણાંક r, authenticated;
	અચલ અક્ષર *displayname;

	જો (!options.gss_authentication)
		fatal_f("GSSAPI authentication not enabled");

	authenticated = authctxt->valid && ssh_gssapi_userok(authctxt->user);

	sshbuf_reset(m);
	જો ((r = sshbuf_put_u32(m, authenticated)) != 0)
		fatal_fr(r, "assemble");

	debug3_f("sending result %d", authenticated);
	mm_request_send(sock, MONITOR_ANS_GSSUSEROK, m);

	auth_method = "gssapi-with-mic";

	જો ((displayname = ssh_gssapi_displayname()) != ખાલી)
		auth2_record_info(authctxt, "%s", displayname);

	/* Monitor loop will terminate if authenticated */
	પાછા (authenticated);
}
#endif /* GSSAPI */

